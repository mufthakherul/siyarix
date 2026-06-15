# SPDX-License-Identifier: AGPL-3.0-or-later

"""Seatbelt Windows enumeration output parser — parses Seatbelt JSON results."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_RE = re.compile(r"^\s*[{\[]")


class SeatbeltParser:
    """Parse Seatbelt JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen_commands: set[str] = set()
        stripped = output.strip()
        if not stripped:
            return findings

        if _JSON_RE.match(stripped):
            try:
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for record in items:
                    if not isinstance(record, dict):
                        continue
                    command = record.get("Command", record.get("command", "Unknown"))
                    host = record.get("Host", record.get("host", "unknown"))
                    output_text = record.get("Output", record.get("output", ""))
                    user = record.get("User", record.get("user", ""))

                    dedup_key = f"{command}|{host}"
                    if dedup_key in seen_commands:
                        continue
                    seen_commands.add(dedup_key)

                    severity = "info"
                    if isinstance(output_text, str):
                        output_lower = output_text.lower()
                        if any(x in output_lower for x in ("admin", "administrator", "password", "token", "privilege")):
                            severity = "high" if "password" in output_lower else "medium"

                    findings.append({
                        "title": f"Seatbelt: {command}",
                        "severity": severity,
                        "description": f"Seatbelt enumerated {command} on {host}"
                        + (f" (user: {user})" if user else ""),
                        "evidence": str(output_text)[:200] if output_text else command,
                        "tool": "seatbelt",
                        "target": host,
                        "timestamp": _now_iso(),
                    })
                return findings
            except json.JSONDecodeError:
                pass

        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            lower = line.lower()
            severity = "info"
            if "password" in lower or "admin" in lower:
                severity = "high" if "password" in lower else "medium"
            dedup_key = f"text|{line[:60]}"
            if dedup_key in seen_commands:
                continue
            seen_commands.add(dedup_key)
            findings.append({
                "title": f"Seatbelt: {line[:60]}",
                "severity": severity,
                "description": f"Seatbelt output: {line[:200]}",
                "evidence": line.strip(),
                "tool": "seatbelt",
                "target": "localhost",
                "timestamp": _now_iso(),
            })

        return findings
