# SPDX-License-Identifier: AGPL-3.0-or-later

"""dnsx JSON output parser — extracts DNS resolutions with host, type, and IP records."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")

_LOOKS_LIKE_JSON_RE = re.compile(r"^\s*[{\[]")

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class DnsxParser:
    """Parse dnsx JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
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
                }
            )

        return findings
