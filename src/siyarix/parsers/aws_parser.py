# SPDX-License-Identifier: AGPL-3.0-or-later

"""AWS CLI output parser — parses AWS CLI JSON output for security findings."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_RE = re.compile(r"^\s*[{\[]")

_KEYS_OF_INTEREST = [
    "PublicAccessBlockConfiguration",
    "PubliclyAccessible",
    "AttachedPolicies",
    "InstanceProfile",
    "Role",
    "PasswordLastUsed",
    "MFA",
    "AccessKeys",
    "Groups",
    "BucketPolicy",
    "IpPermissions",
    "IpRanges",
    "GroupId",
    "UserId",
    "Effect",
    "Principal",
    "Action",
    "Resource",
    "CloudTrail",
    "Logs",
    "KmsKeyId",
    "Encryption",
]


class AwsParser:
    """Parse AWS CLI JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        if not _JSON_RE.match(output):
            return findings

        try:
            data = json.loads(output)
            self._walk("", data, findings)
        except json.JSONDecodeError:
            pass

        if not findings:
            for line in output.splitlines():
                line = line.strip()
                if any(k.lower() in line.lower() for k in _KEYS_OF_INTEREST):
                    findings.append(
                        {
                            "title": f"AWS: {line.split(':')[0].strip()[:60]}",
                            "severity": "info",
                            "description": line.strip()[:200],
                            "evidence": line.strip()[:200],
                            "tool": "aws",
                            "target": "aws-cloud",
                            "timestamp": _now_iso(),
                        }
                    )

        return findings

    def _walk(self, prefix: str, node, findings: list[dict]) -> None:  # type: ignore
        if isinstance(node, dict):
            for k, v in node.items():
                path = f"{prefix}.{k}" if prefix else k
                lower_k = k.lower()
                if isinstance(v, (dict, list)):
                    self._walk(path, v, findings)
                elif isinstance(v, str) and len(v) > 3 and len(v) < 500:
                    severity = "info"
                    if any(
                        x in lower_k
                        for x in (
                            "public",
                            "expose",
                            "open",
                            "password",
                            "secret",
                            "key",
                            "arn:aws:iam",
                        )
                    ):
                        severity = (
                            "high" if "secret" in lower_k or "password" in lower_k else "medium"
                        )
                    findings.append(
                        {
                            "title": f"AWS {path[-60:]}",
                            "severity": severity,
                            "description": f"AWS CLI returned {k}: {v[:120]}",
                            "evidence": f"{k}: {v[:200]}",
                            "tool": "aws",
                            "target": "aws-cloud",
                            "timestamp": _now_iso(),
                        }
                    )
        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._walk(f"{prefix}[{i}]", item, findings)
