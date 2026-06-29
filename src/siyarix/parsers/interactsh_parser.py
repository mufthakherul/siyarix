# SPDX-License-Identifier: AGPL-3.0-or-later

"""Interactsh OOB interaction output parser — parses Interactsh JSON logs."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso


class InteractshParser:
    """Parse interactsh JSON interaction logs into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            protocol = record.get("protocol", "unknown").upper()
            unique_id = record.get("unique-id", "")
            full_id = record.get("full-id", record.get("id", ""))
            remote = record.get("remote-address", record.get("remote", "unknown"))
            timestamp = record.get("timestamp", record.get("time", _now_iso()))
            raw = record.get("raw-request", record.get("request", ""))

            dedup_key = unique_id or full_id or f"{remote}:{protocol}:{timestamp}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "high"
            if protocol in ("HTTP", "HTTPS"):
                severity = "high"
            elif protocol == "DNS":
                severity = "medium"
            elif protocol == "SMTP":
                severity = "critical"
            else:
                severity = "medium"

            if "cookie" in raw.lower() or "authorization" in raw.lower():
                severity = "critical"

            findings.append(
                {
                    "title": f"OOB {protocol} interaction from {remote}",
                    "severity": severity,
                    "description": f"interactsh received {protocol} interaction from {remote}"
                    + (f" (id: {unique_id})" if unique_id else ""),
                    "evidence": f"Protocol: {protocol} | Remote: {remote}"
                    + (f"\nRaw: {raw[:200]}" if raw else ""),
                    "tool": "interactsh",
                    "target": remote,
                    "timestamp": timestamp,
                },
            )

        return findings
