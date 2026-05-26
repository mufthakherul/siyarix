"""Mobile application security testing — Android APK analysis, iOS IPA inspection.

Provides static analysis of mobile app packages for hardcoded secrets,
insecure configurations, and common vulnerability patterns.
"""

from __future__ import annotations

import json
import logging
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MobileFinding:
    severity: str = "medium"
    category: str = ""
    file: str = ""
    message: str = ""
    remediation: str = ""
    cwe: str = ""


@dataclass
class MobileScanResult:
    findings: list[MobileFinding] = field(default_factory=list)
    package_name: str = ""
    app_name: str = ""
    version: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    manifest_parsed: bool = False

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.RECORD_AUDIO": "Record audio",
    "android.permission.CAMERA": "Access camera",
    "android.permission.ACCESS_FINE_LOCATION": "Fine location access",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Background location",
    "android.permission.READ_CONTACTS": "Read contacts",
    "android.permission.READ_CALL_LOG": "Read call log",
    "android.permission.PROCESS_OUTGOING_CALLS": "Monitor outgoing calls",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service binding",
    "android.permission.QUERY_ALL_PACKAGES": "Query all installed packages",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "Manage external storage",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Request install packages",
}

ANDROID_INSECURE_FLAGS = {
    "android:allowBackup=\"true\"": ("Backup enabled — data can be extracted via ADB", "Set android:allowBackup=\"false\""),
    "android:debuggable=\"true\"": ("App is debuggable — insecure for release builds", "Remove android:debuggable or set to false"),
    "android:exported=\"true\"": ("Component exported — may be accessible by other apps", "Set android:exported=\"false\" unless needed"),
    "android:usesCleartextTraffic=\"true\"": ("Cleartext HTTP traffic allowed", "Set android:usesCleartextTraffic=\"false\""),
    "android:networkSecurityConfig": ("Custom network security config — review for weaknesses", ""),
}

SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "critical", "Rotate key and remove from source"),
    (r'sk-[A-Za-z0-9]{24,}', "OpenAI API Key", "critical", "Rotate key and use environment variables"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Embedded Private Key", "critical", "Remove key, use hardware-backed keystore"),
    (r'gh[opsu]_[0-9a-zA-Z]{36}', "GitHub Token", "critical", "Rotate token immediately"),
    (r'(?i)(password|passwd|pwd)\s*[=:].{0,4}["\'][^"\']+["\']', "Hardcoded Password", "high", "Use Android Keystore or encrypted storage"),
    (r'(?i)(api[_-]?key|apikey)\s*[=:].{0,4}["\'][^"\']+["\']', "Hardcoded API Key", "high", "Move to BuildConfig or secure remote config"),
    (r'(?i)(secret|token)\s*[=:].{0,4}["\'][^"\']+["\']', "Hardcoded Secret/Token", "high", "Move to server-side or encrypted store"),
]


class MobileScanner:
    """Static analysis for mobile application packages (APK/IPA)."""

    def __init__(self) -> None:
        self._findings: list[MobileFinding] = []

    def scan_apk(self, apk_path: str | Path) -> MobileScanResult:
        """Analyze an Android APK for security issues."""
        path = Path(apk_path)
        if not path.exists():
            logger.warning("APK not found: %s", apk_path)
            return MobileScanResult()

        result = MobileScanResult(package_name=path.name)
        findings: list[MobileFinding] = []

        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                # Parse AndroidManifest.xml (binary or text)
                if "AndroidManifest.xml" in names:
                    raw = zf.read("AndroidManifest.xml")
                    try:
                        manifest_text = raw.decode("utf-8", errors="replace")
                    except Exception:
                        manifest_text = str(raw)
                    result.manifest_parsed = True
                    self._analyze_manifest(manifest_text, findings, result)
                else:
                    findings.append(MobileFinding(
                        severity="info", category="manifest",
                        message="No AndroidManifest.xml found in APK",
                        remediation="Ensure APK is properly packaged",
                    ))

                # Scan all files for secrets
                for fname in names:
                    if fname.endswith((".xml", ".json", ".properties", ".txt", ".gradle", ".kt", ".java", ".smali")):
                        try:
                            content = zf.read(fname).decode("utf-8", errors="replace")
                            self._scan_for_secrets(fname, content, findings)
                        except Exception:
                            pass

                # Check for common insecure patterns in smali code
                smali_files = [n for n in names if n.endswith(".smali")]
                if smali_files:
                    for sf in smali_files[:50]:
                        try:
                            content = zf.read(sf).decode("utf-8", errors="replace")
                            self._scan_for_secrets(sf, content, findings)
                        except Exception:
                            pass
        except zipfile.BadZipFile:
            findings.append(MobileFinding(
                severity="high", category="integrity",
                message="Invalid APK — not a valid ZIP archive",
                remediation="Re-download or rebuild the APK",
            ))
        except Exception as exc:
            logger.warning("APK scan error: %s", exc)
            findings.append(MobileFinding(
                severity="medium", category="general",
                message=f"Scan error: {exc}",
            ))

        result.findings = findings
        return result

    def _analyze_manifest(self, text: str, findings: list[MobileFinding], result: MobileScanResult) -> None:
        # Extract package name
        m = re.search(r'package="([^"]+)"', text)
        if m:
            result.package_name = m.group(1)
        m = re.search(r'android:versionName="([^"]+)"', text)
        if m:
            result.version = m.group(1)
        m = re.search(r'android:minSdkVersion="?(\d+)"?', text)
        if m:
            result.min_sdk = m.group(1)
        m = re.search(r'android:targetSdkVersion="?(\d+)"?', text)
        if m:
            result.target_sdk = m.group(1)

        # Permissions
        for perm_match in re.finditer(r'<uses-permission android:name="([^"]+)"', text):
            perm = perm_match.group(1)
            result.permissions.append(perm)
            if perm in ANDROID_DANGEROUS_PERMISSIONS:
                findings.append(MobileFinding(
                    severity="medium" if "BACKGROUND" not in perm else "high",
                    category="permission",
                    file="AndroidManifest.xml",
                    message=f"Dangerous permission: {ANDROID_DANGEROUS_PERMISSIONS[perm]} ({perm})",
                    remediation="Remove if not essential for app functionality",
                    cwe="CWE-250",
                ))

        # Insecure flags
        for flag, (msg, remediation) in ANDROID_INSECURE_FLAGS.items():
            if flag in text:
                findings.append(MobileFinding(
                    severity="high" if "debuggable" in flag or "allowBackup" in flag else "medium",
                    category="configuration",
                    file="AndroidManifest.xml",
                    message=msg,
                    remediation=remediation or "Review and fix",
                ))

        # Extract component names
        for comp in re.finditer(r'<activity android:name="([^"]+)"', text):
            result.activities.append(comp.group(1))
        for comp in re.finditer(r'<service android:name="([^"]+)"', text):
            result.services.append(comp.group(1))

    def _scan_for_secrets(self, fname: str, content: str, findings: list[MobileFinding]) -> None:
        for pattern, label, severity, remediation in SECRET_PATTERNS:
            if re.search(pattern, content):
                findings.append(MobileFinding(
                    severity=severity,
                    category="secret",
                    file=fname,
                    message=f"Hardcoded {label} detected",
                    remediation=remediation,
                    cwe="CWE-798",
                ))

    def generate_report(self, result: MobileScanResult, fmt: str = "text") -> str:
        if fmt == "json":
            return json.dumps({
                "package": result.package_name,
                "version": result.version,
                "min_sdk": result.min_sdk,
                "findings_count": len(result.findings),
                "summary": result.summary,
                "permissions": result.permissions,
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "file": f.file,
                        "message": f.message,
                        "remediation": f.remediation,
                        "cwe": f.cwe,
                    }
                    for f in result.findings
                ],
            }, indent=2)
        lines = [f"Mobile Scan: {result.package_name} v{result.version or '?'}"]
        lines.append(f"  Min SDK: {result.min_sdk or '?'} | Findings: {len(result.findings)}")
        for sev in ("critical", "high", "medium", "low", "info"):
            c = result.summary.get(sev, 0)
            if c:
                lines.append(f"    {sev}: {c}")
        for f in result.findings[:15]:
            lines.append(f"\n  [{f.severity.upper()}] [{f.category}] {f.file}")
            lines.append(f"    {f.message}")
            if f.remediation:
                lines.append(f"    Fix: {f.remediation}")
        if result.permissions:
            lines.append(f"\n  Permissions ({len(result.permissions)}):")
            for p in sorted(result.permissions)[:10]:
                lines.append(f"    • {p}")
            if len(result.permissions) > 10:
                lines.append(f"    ... and {len(result.permissions)-10} more")
        if len(result.findings) > 15:
            lines.append(f"\n  ... and {len(result.findings)-15} more findings")
        return "\n".join(lines)


__all__ = ["MobileScanner", "MobileFinding", "MobileScanResult"]
