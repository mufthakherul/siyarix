# SPDX-License-Identifier: AGPL-3.0-or-later

"""Infrastructure as Code security scanning — Terraform, CloudFormation, Helm, Dockerfile.

Analyzes IaC templates for misconfigurations, hardcoded secrets,
overly permissive policies, and compliance violations.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class IaCFinding:
    file: str = ""
    line: int = 0
    severity: str = "medium"
    rule: str = ""
    message: str = ""
    remediation: str = ""
    code_snippet: str = ""


@dataclass
class IaCScanResult:
    findings: list[IaCFinding] = field(default_factory=list)
    files_scanned: int = 0
    total_lines: int = 0

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


TF_DANGEROUS_PATTERNS: list[tuple[str, str, str, str]] = [
    (r's3_bucket.*acl.*public-read', "S3 bucket public-read ACL", "high", "Set acl to private or use bucket policies"),
    (r's3_bucket.*acl.*public-read-write', "S3 bucket public-read-write ACL", "critical", "Set acl to private immediately"),
    (r'ingress.*cidr_blocks.*\[\"0\.0\.0\.0/0\"\]', "Security group allows all inbound traffic", "high", "Restrict ingress CIDR to specific IPs"),
    (r'ingress.*cidr_blocks.*\[\"::/0\"\]', "Security group allows all IPv6 inbound", "high", "Restrict ingress CIDR to specific IPv6 ranges"),
    (r'iam_role_policy.*Action.*\"\*\"', "IAM policy with wildcard Action", "medium", "Scope IAM actions to least privilege"),
    (r'iam_role_policy.*Resource.*\"\*\"', "IAM policy with wildcard Resource", "medium", "Scope IAM resources to least privilege"),
    (r'password.*true.*false', "Password authentication enabled", "medium", "Disable password auth, use SSH keys"),
    (r'admin_password|db_password.*=.*\"[^\"]+\"', "Hardcoded password in template", "critical", "Use secret manager or variable reference"),
    (r'access_key.*=.*\"[A-Z0-9]{20}\"', "Hardcoded AWS access key", "critical", "Use IAM roles instead of access keys"),
    (r'secret_key.*=.*\"[A-Za-z0-9/+=]{40}\"', "Hardcoded AWS secret key", "critical", "Use IAM roles instead of secret keys"),
    (r'encryption.*false', "Encryption disabled", "high", "Enable encryption for data at rest"),
    (r'ssl.*false|tls.*false|https.*false', "TLS/SSL disabled", "high", "Enable TLS for all communications"),
    (r'kms_key_id.*\"\"', "Empty KMS key ID", "medium", "Specify a valid KMS key"),
    (r'logging.*false|log.*disabled', "Logging disabled", "medium", "Enable logging for audit trail"),
    (r'backup.*false|backup.*disabled', "Backup disabled", "low", "Enable automated backups"),
    (r'multi_az.*false', "Multi-AZ disabled", "low", "Enable Multi-AZ for high availability"),
    (r'deletion_protection.*false', "Deletion protection disabled", "medium", "Enable deletion protection"),
]

CFN_DANGEROUS_PATTERNS: list[tuple[str, str, str, str]] = [
    (r'CidrIp:\s*0\.0\.0\.0/0', "CloudFormation: security group open to world", "high", "Restrict CidrIp to specific IP range"),
    (r'Effect:\s*Allow\s*\n.*Action:\s*\*', "CloudFormation: IAM wildcard Action", "medium", "Scope actions to least privilege"),
    (r'\"Ref\":\s*\"AWS::NoValue\"', "CloudFormation: reference to NoValue", "low", "Remove unused reference"),
]

HELM_DANGEROUS_PATTERNS: list[tuple[str, str, str, str]] = [
    (r'privileged:\s*true', "Helm: privileged container", "high", "Set privileged to false"),
    (r'allowPrivilegeEscalation:\s*true', "Helm: privilege escalation allowed", "high", "Set allowPrivilegeEscalation to false"),
    (r'runAsNonRoot:\s*false', "Helm: container runs as root", "medium", "Set runAsNonRoot to true"),
    (r'readOnlyRootFilesystem:\s*false', "Helm: writable root filesystem", "medium", "Set readOnlyRootFilesystem to true"),
    (r'capabilities:\s*add:\s*- ALL', "Helm: all capabilities added", "medium", "Drop all capabilities and add only needed"),
    (r'hostNetwork:\s*true', "Helm: host network access", "high", "Set hostNetwork to false"),
    (r'image:\s*latest', "Helm: using latest image tag", "low", "Pin to a specific version tag"),
]

SINGLE_Q = chr(39)  # single quote for regex char class
DOUBLE_Q = chr(34)  # double quote
SECRET_PATTERNS: list[tuple[str, str]] = [
    (f'(?i)password\\s*[=:].{{0,4}}[{SINGLE_Q}{DOUBLE_Q}><]?\\w+[{SINGLE_Q}{DOUBLE_Q}><]?\\s*$', "Possible hardcoded password"),
    (f'(?i)secret\\s*[=:].{{0,4}}[{SINGLE_Q}{DOUBLE_Q}><]?\\w+[{SINGLE_Q}{DOUBLE_Q}><]?\\s*$', "Possible hardcoded secret"),
    (f'(?i)api[_-]?key\\s*[=:].{{0,4}}[{SINGLE_Q}{DOUBLE_Q}><]?\\w+[{SINGLE_Q}{DOUBLE_Q}><]?\\s*$', "Possible hardcoded API key"),
    (f'(?i)token\\s*[=:].{{0,4}}[{SINGLE_Q}{DOUBLE_Q}><]?\\w+[{SINGLE_Q}{DOUBLE_Q}><]?\\s*$', "Possible hardcoded token"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Embedded private key"),
    (r'gh[opsu]_[0-9a-zA-Z]{36}', "GitHub token detected"),
    (r'sk-[A-Za-z0-9]{24,}', "OpenAI API key detected"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID detected"),
]


class IaCScanner:
    """Scans Infrastructure as Code files for security issues."""

    def __init__(self) -> None:
        self._findings: list[IaCFinding] = []

    def scan_path(self, path: str | Path, recursive: bool = True) -> IaCScanResult:
        root = Path(path)
        if not root.exists():
            logger.warning("IaC scan path does not exist: %s", path)
            return IaCScanResult()

        patterns = ["*.tf", "*.tfvars", "*.yaml", "*.yml", "*.json", "*.dockerfile", "Dockerfile"]
        files: list[Path] = []
        if root.is_file():
            files = [root]
        elif recursive:
            for pat in patterns:
                files.extend(root.rglob(pat))
        else:
            for pat in patterns:
                files.extend(root.glob(pat))

        for f in files:
            self._scan_file(f)

        result = IaCScanResult(findings=self._findings, files_scanned=len(files))
        return result

    def _scan_file(self, filepath: Path) -> None:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.debug("Cannot read %s: %s", filepath, exc)
            return

        lines = content.split("\n")
        ext = filepath.suffix.lower()
        name = filepath.name.lower()

        if ext == ".tf" or ext == ".tfvars":
            patterns = TF_DANGEROUS_PATTERNS
        elif ext == ".json" and "cloudformation" in name.lower():
            patterns = CFN_DANGEROUS_PATTERNS
        elif name in ("Dockerfile",) or ext == ".dockerfile":
            patterns = []
            for p, msg, sev, rem in HELM_DANGEROUS_PATTERNS:
                if any(kw in p for kw in ("privileged", "root", "latest")):
                    patterns.append((p, msg, sev, rem))
        elif ext in (".yaml", ".yml"):
            if "chart" in name.lower() or "values" in name.lower():
                patterns = HELM_DANGEROUS_PATTERNS
            else:
                patterns = TF_DANGEROUS_PATTERNS
        else:
            patterns = TF_DANGEROUS_PATTERNS + CFN_DANGEROUS_PATTERNS

        for i, line in enumerate(lines, 1):
            for pattern, message, severity, remediation in patterns:
                if re.search(pattern, line):
                    self._findings.append(
                        IaCFinding(
                            file=str(filepath),
                            line=i,
                            severity=severity,
                            rule=message,
                            message=message,
                            remediation=remediation,
                            code_snippet=line.strip()[:120],
                        )
                    )
            for pattern, message in SECRET_PATTERNS:
                if re.search(pattern, line):
                    self._findings.append(
                        IaCFinding(
                            file=str(filepath),
                            line=i,
                            severity="critical" if "PRIVATE KEY" in line else "high",
                            rule="hardcoded_secret",
                            message=message,
                            remediation="Move to secret manager or environment variable",
                            code_snippet=line.strip()[:60],
                        )
                    )

    def generate_report(self, result: IaCScanResult, fmt: str = "text") -> str:
        if fmt == "json":
            return json.dumps(
                {
                    "files_scanned": result.files_scanned,
                    "total_findings": len(result.findings),
                    "summary": result.summary,
                    "findings": [
                        {
                            "file": f.file,
                            "line": f.line,
                            "severity": f.severity,
                            "rule": f.rule,
                            "message": f.message,
                            "remediation": f.remediation,
                        }
                        for f in result.findings
                    ],
                },
                indent=2,
            )
        lines = [f"IaC Scan Results: {len(result.findings)} findings across {result.files_scanned} files"]
        lines.append(f"  Critical: {result.summary.get('critical', 0)}")
        lines.append(f"  High: {result.summary.get('high', 0)}")
        lines.append(f"  Medium: {result.summary.get('medium', 0)}")
        lines.append(f"  Low: {result.summary.get('low', 0)}")
        for f in result.findings[:20]:
            lines.append(f"\n  [{f.severity.upper()}] {f.file}:{f.line}")
            lines.append(f"    {f.message}")
            lines.append(f"    Fix: {f.remediation}")
        if len(result.findings) > 20:
            lines.append(f"\n  ... and {len(result.findings) - 20} more findings")
        return "\n".join(lines)


__all__ = ["IaCScanner", "IaCFinding", "IaCScanResult"]
