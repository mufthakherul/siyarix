# SPDX-License-Identifier: AGPL-3.0-or-later

"""Findomain JSON output parser — extracts resolved domains with IP addresses."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso


class FindomainParser:
    """Parse findomain JSON output (one JSON per line) into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            domain = obj.get("domain", obj.get("Domain", ""))
            if not domain or domain in seen:
                continue
            seen.add(domain)

            ip_address = obj.get(
                "ip_address", obj.get("ip", obj.get("IP", obj.get("IpAddress", ""))),
            )

            description = f"Domain resolved: {domain}"
            evidence = domain
            if ip_address:
                description += f" -> {ip_address}"
                evidence += f" -> {ip_address}"

            findings.append(
                {
                    "title": f"Findomain: {domain}",
                    "severity": "info",
                    "description": description,
                    "evidence": evidence,
                    "tool": "findomain",
                    "target": domain,
                    "timestamp": _now_iso(),
                },
            )

        return findings
