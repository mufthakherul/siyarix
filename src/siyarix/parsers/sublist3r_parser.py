# SPDX-License-Identifier: AGPL-3.0-or-later

"""Sublist3r output parser — parses subdomain enumeration text output."""

from __future__ import annotations

from . import _now_iso

import re

_SUBDOMAIN_RE = re.compile(
    r"(?P<subdomain>[a-zA-Z0-9][\w\-\.]+[a-zA-Z0-9])\s*[\(\[_]?(?P<ip>[\d.]+)?[\)\]_]?",
)

_SECTION_RE = re.compile(
    r"#\s*(?:Total\s+)?(?:unique\s+)?(?:sub)?domains?\s+(?:found|discovered)",
    re.IGNORECASE,
)


class Sublist3rParser:
    """Parse Sublist3r output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        base_domain = "unknown"
        in_results = False

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if _SECTION_RE.search(line):
                in_results = True
                continue

            lower = line.lower()
            if "sublist3r" in lower and "domain" in lower:
                parts = line.rsplit(":", 1)
                if len(parts) > 1:
                    base_domain = parts[-1].strip()

            if _SUBDOMAIN_RE.match(line):
                sub = _SUBDOMAIN_RE.match(line).group("subdomain").rstrip(".")  # type: ignore
                ip = _SUBDOMAIN_RE.match(line).group("ip") or ""  # type: ignore
                findings.append(
                    {
                        "title": f"Subdomain: {sub}",
                        "severity": "info",
                        "description": f"Sublist3r discovered subdomain {sub} under {base_domain}"
                        + (f" (IP: {ip})" if ip else ""),
                        "evidence": f"{sub}" + (f" [{ip}]" if ip else ""),
                        "tool": "sublist3r",
                        "target": sub,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if not in_results:
                continue

            m = _SUBDOMAIN_RE.match(line)
            if m:
                sub = m.group("subdomain").rstrip(".")
                ip = m.group("ip") or ""
                findings.append(
                    {
                        "title": f"Subdomain: {sub}",
                        "severity": "info",
                        "description": f"Sublist3r discovered subdomain {sub} under {base_domain}"
                        + (f" (IP: {ip})" if ip else ""),
                        "evidence": f"{sub}" + (f" [{ip}]" if ip else ""),
                        "tool": "sublist3r",
                        "target": sub,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
