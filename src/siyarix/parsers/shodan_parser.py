# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shodan output parser — parses Shodan CLI JSON output."""

from __future__ import annotations

from . import _now_iso

import json

class ShodanParser:
    """Parses Shodan JSON output into finding dicts."""

    def parse(self, json_output: str) -> list[dict]:
        """Parse Shodan JSON output and return a list of finding dicts."""
        findings: list[dict] = []

        # Shodan CLI `shodan host --save json` or similar often produces JSONL
        for line in json_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip_str = record.get("ip_str", "unknown")
            org = record.get("org", "unknown")
            os = record.get("os", "unknown")
            ports = record.get("ports", [])
            vulns = record.get("vulns", [])

            # Host summary finding
            findings.append(
                {
                    "title": f"Shodan Host: {ip_str}",
                    "severity": "info",
                    "description": f"Shodan record for {ip_str}. Org: {org}, OS: {os}, Ports: {ports}",
                    "evidence": f"Ports: {ports}",
                    "tool": "shodan",
                    "target": ip_str,
                    "timestamp": _now_iso(),
                }
            )

            # Add vulnerabilities if any
            for vuln in vulns:
                findings.append(
                    {
                        "title": f"Shodan Vulnerability: {vuln}",
                        "severity": "high",  # Defaulting to high for CVEs
                        "description": f"Shodan reported CVE {vuln} on {ip_str}",
                        "evidence": f"CVE: {vuln}",
                        "tool": "shodan",
                        "target": ip_str,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
