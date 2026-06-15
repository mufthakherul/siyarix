# SPDX-License-Identifier: AGPL-3.0-or-later

"""Findomain JSON output parser — extracts resolved domains with IP addresses."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")


class FindomainParser:
    """Parse findomain JSON output (one JSON per line) into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped or not _JSON_LINE_RE.match(line_stripped):
                continue

            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            domain = obj.get("domain", obj.get("Domain", ""))
            if not domain or domain in seen:
                continue
            seen.add(domain)

            ip_address = obj.get("ip_address", obj.get("ip", obj.get("IP", obj.get("IpAddress", ""))))

            description = f"Domain resolved: {domain}"
            evidence = domain
            if ip_address:
                description += f" -> {ip_address}"
                evidence += f" -> {ip_address}"

            findings.append({
                "title": f"Findomain: {domain}",
                "severity": "info",
                "description": description,
                "evidence": evidence,
                "tool": "findomain",
                "target": domain,
                "timestamp": _now_iso(),
            })

        return findings
