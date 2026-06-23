# SPDX-License-Identifier: AGPL-3.0-or-later

"""Assetfinder subdomain discovery output parser."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_SUBDOMAIN_RE = re.compile(
    r"^(?P<sub>[a-zA-Z0-9][\w.\-]*[a-zA-Z0-9])\s*$",
)

_SUMMARY_RE = re.compile(
    r"(?:subdomains?|found|total|scanned)[:\s]*(\d+)",
    re.IGNORECASE,
)


class AssetfinderParser:
    """Parse assetfinder output (one subdomain per line) into findings."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        summary_m = _SUMMARY_RE.search(output)
        summary_count = summary_m.group(1) if summary_m else None

        for raw in output.splitlines():
            line = raw.strip()
            if not line or line in seen:
                continue
            m = _SUBDOMAIN_RE.match(line)
            if m:
                sub = m.group("sub")
                seen.add(sub)
                findings.append(
                    {
                        "title": f"Subdomain: {sub}",
                        "severity": "info",
                        "description": f"assetfinder discovered subdomain {sub}",
                        "evidence": sub,
                        "tool": "assetfinder",
                        "target": sub,
                        "timestamp": _now_iso(),
                    },
                )

        if summary_count:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"assetfinder: {summary_count} subdomains",
                        "severity": "info",
                        "description": f"assetfinder discovered {summary_count} subdomains",
                        "evidence": f"Total: {summary_count}",
                        "tool": "assetfinder",
                        "target": "",
                        "timestamp": _now_iso(),
                    },
                )

        return findings
