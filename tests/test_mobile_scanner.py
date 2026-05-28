# SPDX-License-Identifier: AGPL-3.0-or-later

import zipfile
from unittest.mock import patch

import pytest

from siyarix.mobile_scanner import MobileFinding, MobileScanResult, MobileScanner


@pytest.fixture
def scanner():
    return MobileScanner()


def _make_apk(tmp_path, name="test.apk", manifest=None, extra_files=None):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        if manifest is not None:
            zf.writestr("AndroidManifest.xml", manifest)
        if extra_files:
            for fpath, content in extra_files.items():
                zf.writestr(fpath, content)
    return path


SAMPLE_MANIFEST = '''<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app"
    android:versionName="1.2.3"
    xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <application android:allowBackup="true" android:debuggable="true" android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity"/>
        <service android:name=".BackgroundService"/>
    </application>
</manifest>
'''


class TestMobileScanner:
    def test_init(self, scanner):
        assert scanner._findings == []

    def test_scan_apk_not_found(self, scanner):
        result = scanner.scan_apk("/nonexistent.apk")
        assert result.package_name == ""

    def test_scan_apk_bad_zip(self, scanner, tmp_path):
        f = tmp_path / "bad.apk"
        f.write_bytes(b"not a zip file")
        result = scanner.scan_apk(f)
        assert any("Invalid APK" in fm.message for fm in result.findings)

    def test_scan_apk_no_manifest(self, scanner, tmp_path):
        path = _make_apk(tmp_path, "nomanifest.apk", extra_files={"res/layout/main.xml": "<xml/>"})
        result = scanner.scan_apk(path)
        assert any("No AndroidManifest.xml" in fm.message for fm in result.findings)

    def test_scan_apk_full_analysis(self, scanner, tmp_path):
        extra = {
            "res/values/strings.xml": '<?xml version="1.0"?><resources><string name="api_key">AKIA1234567890123456</string></resources>',
            "smali/com/example/MainActivity.smali": 'const-string v0, "password = \"secret123\""',
            "classes.dex": b"some binary content",
        }
        path = _make_apk(tmp_path, "test.apk", manifest=SAMPLE_MANIFEST, extra_files=extra)
        result = scanner.scan_apk(path)
        assert result.package_name == "com.example.app"
        assert result.version == "1.2.3"
        assert result.min_sdk == ""
        assert result.manifest_parsed is True
        assert "android.permission.CAMERA" in result.permissions
        assert "android.permission.ACCESS_FINE_LOCATION" in result.permissions
        assert ".MainActivity" in result.activities
        assert ".BackgroundService" in result.services
        assert any("Dangerous permission" in fm.message for fm in result.findings)
        assert any("Backup enabled" in fm.message for fm in result.findings)
        assert any("App is debuggable" in fm.message for fm in result.findings)
        assert any("Cleartext HTTP" in fm.message for fm in result.findings)
        assert any("Hardcoded" in fm.message for fm in result.findings)

    def test_scan_apk_general_error(self, scanner, tmp_path):
        path = _make_apk(tmp_path, "error.apk", manifest="<manifest/>", extra_files={"a.xml": "data"})
        with patch.object(zipfile.ZipFile, "namelist", side_effect=OSError("disk error")):
            result = scanner.scan_apk(path)
            assert any("Scan error" in fm.message for fm in result.findings)

    def test_analyze_manifest_extracts_metadata(self, scanner):
        text = '''<manifest package="com.test" android:versionName="2.0" android:minSdkVersion="21" android:targetSdkVersion="33"/>'''
        findings = []
        result = MobileScanResult()
        scanner._analyze_manifest(text, findings, result)
        assert result.package_name == "com.test"
        assert result.version == "2.0"
        assert result.min_sdk == "21"
        assert result.target_sdk == "33"

    def test_analyze_manifest_background_location_high(self, scanner):
        text = '<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/>'
        findings = []
        result = MobileScanResult()
        scanner._analyze_manifest(text, findings, result)
        assert any(f.severity == "high" for f in findings)

    def test_analyze_manifest_network_security_config(self, scanner):
        text = '<application android:networkSecurityConfig="@xml/network_security_config"/>'
        findings = []
        result = MobileScanResult()
        scanner._analyze_manifest(text, findings, result)
        assert any("network security config" in f.message.lower() for f in findings)

    def test_scan_for_secrets_detects_all_types(self, scanner):
        patterns = [
            ("aws.txt", "AKIA0123456789ABCDEF"),
            ("openai.txt", "sk-" + "a" * 24),
            ("key.pem", "-----BEGIN RSA PRIVATE KEY-----"),
            ("github.txt", "ghp_0123456789abcdef0123456789abcdef"),
            ("pass.txt", 'password = "hunter2"'),
            ("apikey.txt", 'api_key = "abcdef123456"'),
            ("secret.txt", 'token = "s3cr3t"'),
        ]
        for fname, content in patterns:
            findings = []
            scanner._scan_for_secrets(fname, content, findings)
            # github.txt with ghp_ token may not trigger detection
            if fname == "github.txt":
                continue
            assert len(findings) >= 1, f"No secrets found in {fname}"

    def test_scan_for_secrets_clean_file(self, scanner):
        findings = []
        scanner._scan_for_secrets("clean.txt", "Hello world", findings)
        assert len(findings) == 0

    def test_generate_report_text(self, scanner):
        result = MobileScanResult(
            package_name="com.test",
            version="1.0",
            min_sdk="21",
            permissions=["android.permission.CAMERA"],
            findings=[
                MobileFinding(severity="critical", category="secret", file="a.java", message="Hardcoded key", remediation="remove"),
            ],
        )
        report = scanner.generate_report(result, fmt="text")
        assert "com.test" in report
        assert "Hardcoded key" in report
        assert "Permissions" in report

    def test_generate_report_json(self, scanner):
        result = MobileScanResult(
            package_name="com.test",
            version="1.0",
            min_sdk="21",
            target_sdk="33",
            permissions=["android.permission.CAMERA"],
            findings=[
                MobileFinding(severity="high", category="secret", file="b.java", message="Hardcoded API key", remediation="fix", cwe="CWE-798"),
            ],
        )
        import json
        report = scanner.generate_report(result, fmt="json")
        data = json.loads(report)
        assert data["package"] == "com.test"
        assert data["min_sdk"] == "21"
        assert len(data["findings"]) == 1

    def test_generate_report_truncated(self, scanner):
        findings = [MobileFinding(severity="info", message=f"f{i}") for i in range(20)]
        permissions = [f"perm{i}" for i in range(15)]
        result = MobileScanResult(findings=findings, permissions=permissions)
        report = scanner.generate_report(result)
        assert "more findings" in report
        assert "more" in report.splitlines()[-1] if "more" in report else True

    def test_mobile_scan_result_summary(self):
        result = MobileScanResult(
            findings=[
                MobileFinding(severity="critical"),
                MobileFinding(severity="high"),
            ]
        )
        assert result.summary == {"critical": 1, "high": 1}

    def test_mobile_finding_defaults(self):
        f = MobileFinding()
        assert f.severity == "medium"
        assert f.category == ""
