# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations
import json
from typing import Any
from . import BaseParser, build_finding


class CorsyParser(BaseParser):
    """Parses Corsy JSON output for CORS misconfigurations."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        findings = []
        try:
            data = json.loads(output)
            for url, details in data.items():
                if isinstance(details, list):
                    for detail in details:
                        issue_type = detail.get("type", "Unknown CORS misconfiguration")
                        severity = detail.get("severity", "low").lower()
                        findings.append(
                            build_finding(
                                title=f"CORS Misconfiguration: {issue_type}",
                                severity=severity,
                                description=f"CORS vulnerability found at {url}",
                                evidence=json.dumps(detail),
                                tool="corsy",
                                target=url,
                            )
                        )
            return findings
        except json.JSONDecodeError:
            pass

        # Fallback to simple text parsing
        for line in output.splitlines():
            if "Vulnerability" in line and "http" in line:
                findings.append(
                    build_finding(
                        title="CORS Misconfiguration",
                        severity="medium",
                        description=line.strip(),
                        evidence=line.strip(),
                        tool="corsy",
                        target="",
                    )
                )
        return findings
