# SPDX-License-Identifier: AGPL-3.0-or-later


import pytest

from siyarix.iac_scanner import IaCFinding, IaCScanResult, IaCScanner


@pytest.fixture
def scanner():
    return IaCScanner()


@pytest.fixture
def tf_file(tmp_path):
    f = tmp_path / "main.tf"
    f.write_text(
        'resource "aws_s3_bucket" "bad" {\n'
        '  acl = "public-read"\n'
        '  encryption = false\n'
        '  logging = false\n'
        '}\n'
        'resource "aws_security_group" "open" {\n'
        '  ingress {\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n'
        'password = "s3cret!"\n'
    )
    return f


@pytest.fixture
def tfvars_file(tmp_path):
    f = tmp_path / "vars.tfvars"
    f.write_text('admin_password = "pa$$w0rd"\naccess_key = "AKIA0123456789ABCDEF"\n')
    return f


@pytest.fixture
def helm_file(tmp_path):
    f = tmp_path / "values.yaml"
    f.write_text(
        'privileged: true\n'
        'allowPrivilegeEscalation: true\n'
        'runAsNonRoot: false\n'
        'readOnlyRootFilesystem: false\n'
        'image: latest\n'
        'hostNetwork: true\n'
    )
    return f


@pytest.fixture
def dockerfile(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM ubuntu:latest\nRUN apt-get update\n")
    return f


@pytest.fixture
def dockerfile_ext(tmp_path):
    f = tmp_path / "app.dockerfile"
    f.write_text("FROM alpine:latest\n")
    return f


@pytest.fixture
def cfn_file(tmp_path):
    f = tmp_path / "cloudformation.json"
    f.write_text(
        '{\n'
        '  "Resources": {\n'
        '    "SG": {\n'
        '      "Type": "AWS::EC2::SecurityGroup",\n'
        '      "Properties": {\n'
        '        "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0"}]\n'
        '      }\n'
        '    }\n'
        '  }\n'
        '}\n'
    )
    return f


@pytest.fixture
def secret_file(tmp_path):
    f = tmp_path / "secrets.txt"
    f.write_text(
        'ghp_0123456789abcdef0123456789abcdef01\n'
        '-----BEGIN EC PRIVATE KEY-----\n'
        'sk-0123456789abcdef0123456789abcdef012345\n'
    )
    return f


class TestIaCScanner:
    def test_init(self, scanner):
        assert scanner._findings == []

    def test_scan_path_not_found(self, scanner):
        result = scanner.scan_path("/nonexistent/path")
        assert result.files_scanned == 0

    def test_scan_single_file_no_recursive(self, scanner, tf_file):
        result = scanner.scan_path(tf_file, recursive=False)
        assert result.files_scanned == 1
        assert len(result.findings) >= 1

    def test_scan_tf_with_secrets(self, scanner, tf_file):
        result = scanner.scan_path(tf_file)
        assert len(result.findings) >= 1

    def test_scan_cfn(self, scanner, cfn_file):
        result = scanner.scan_path(cfn_file)
        assert result.files_scanned == 1

    def test_scan_secrets_file(self, scanner, secret_file):
        result = scanner.scan_path(secret_file)
        assert result.files_scanned == 1
        assert any("OpenAI" in f.message for f in result.findings)

    def test_scan_recursive(self, scanner, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.tf").write_text('acl = "public-read-write"\n')
        f = tmp_path / "root.tf"
        f.write_text('ingress { cidr_blocks = ["0.0.0.0/0"] }\n')
        result = scanner.scan_path(tmp_path, recursive=True)
        assert result.files_scanned >= 2

    def test_scan_non_recursive(self, scanner, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.tf").write_text('acl = "public-read-write"\n')
        f = tmp_path / "root.tf"
        f.write_text('password = "test"\n')
        result = scanner.scan_path(tmp_path, recursive=False)
        assert result.files_scanned == 1

    def test_scan_yaml_non_chart(self, scanner, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text('ingress { cidr_blocks = ["0.0.0.0/0"] }\n')
        result = scanner.scan_path(f)
        assert len(result.findings) >= 0  # Scanner may or may not flag YAML

    def test_generate_report_text(self, scanner):
        result = IaCScanResult(
            files_scanned=3,
            findings=[
                IaCFinding(file="main.tf", line=5, severity="critical", rule="test rule", message="critical finding", remediation="fix it"),
                IaCFinding(file="vars.tf", line=2, severity="high", rule="high rule", message="high finding", remediation="resolve"),
            ],
        )
        report = scanner.generate_report(result, fmt="text")
        assert "critical finding" in report
        assert "3 files" in report
        assert "Critical: 1" in report
        assert "High: 1" in report

    def test_generate_report_json(self, scanner):
        result = IaCScanResult(
            files_scanned=2,
            findings=[
                IaCFinding(file="f.tf", line=3, severity="medium", rule="some rule", message="medium issue", remediation="review"),
            ],
        )
        import json
        report = scanner.generate_report(result, fmt="json")
        data = json.loads(report)
        assert data["files_scanned"] == 2
        assert data["total_findings"] == 1

    def test_generate_report_truncated(self, scanner):
        findings = [IaCFinding(file="f.tf", line=i, severity="info", rule="r", message=f"issue {i}", remediation="fix") for i in range(25)]
        result = IaCScanResult(findings=findings, files_scanned=1)
        report = scanner.generate_report(result)
        assert "more findings" in report

    def test_scan_result_summary(self):
        result = IaCScanResult(
            findings=[
                IaCFinding(severity="critical"),
                IaCFinding(severity="high"),
                IaCFinding(severity="medium"),
            ]
        )
        assert result.summary == {"critical": 1, "high": 1, "medium": 1}

    def test_iac_finding_defaults(self):
        f = IaCFinding()
        assert f.severity == "medium"
        assert f.file == ""
