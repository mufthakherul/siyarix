# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shuffledns output parser — parses domain-to-IP resolution lines from shuffledns plain-text output."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_LINE_RE = re.compile(r"^(\S+)\s*[:,\t]\s*(\S+)$")
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DOMAIN_RE = re.compile(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")


class ShufflednsParser:
    """Parse shuffledns plain-text output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            m = _LINE_RE.match(line_stripped)
            if m:
                domain = m.group(1).strip()
                ip = m.group(2).strip()
            elif _IP_RE.match(line_stripped):
                ip = line_stripped
                domain = "unknown"
            elif _DOMAIN_RE.match(line_stripped):
                domain = line_stripped
                ip = ""
            else:
                continue

            if domain in seen:
                continue
            seen.add(domain)

            description = f"Resolved domain: {domain}"
            evidence = domain
            if ip:
                description += f" -> {ip}"
                evidence += f" : {ip}"

            findings.append(
                {
                    "title": f"Shuffledns: {domain}",
                    "severity": "info",
                    "description": description,
                    "evidence": evidence,
                    "tool": "shuffledns",
                    "target": domain,
                    "timestamp": _now_iso(),
                },
            )

        return findings
