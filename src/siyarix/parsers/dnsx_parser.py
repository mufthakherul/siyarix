# SPDX-License-Identifier: AGPL-3.0-or-later

"""dnsx JSON output parser — extracts DNS resolutions with host, type, and IP records."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_LOOKS_LIKE_JSON_RE = re.compile(r"^\s*[{\[]")


class DnsxParser:
    """Parse dnsx JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if _LOOKS_LIKE_JSON_RE.match(line_stripped):
                try:
                    obj = json.loads(line_stripped)
                except json.JSONDecodeError:
                    continue
            else:
                continue

            host = obj.get("host", obj.get("Host", ""))
            if not host:
                continue

            record_type = obj.get("type", obj.get("Type", ""))
            resolved_ips = obj.get("a", obj.get("A", obj.get("ip", obj.get("IP", ""))))

            if isinstance(resolved_ips, list):
                resolved_ips = ", ".join(resolved_ips)

            dedup_key = f"{host}:{record_type}:{resolved_ips}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            description = f"DNS resolution: {host}"
            if record_type:
                description += f" [{record_type}]"
            if resolved_ips:
                description += f" -> {resolved_ips}"

            findings.append(
                {
                    "title": f"dnsx: {host}",
                    "severity": "info",
                    "description": description,
                    "evidence": f"Host: {host}, Type: {record_type}, Records: {resolved_ips}",
                    "tool": "dnsx",
                    "target": host,
                    "timestamp": _now_iso(),
                },
            )

        return findings
