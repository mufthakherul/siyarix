# SPDX-License-Identifier: AGPL-3.0-or-later

"""Amass output parser — parses amass JSONL output."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso


class AmassParser:
    """Parses OWASP Amass JSONL output into finding dicts."""

    def parse(self, jsonl_output: str) -> list[dict[str, Any]]:
        """Parse amass JSONL output and return a list of finding dicts."""
        if not jsonl_output or not jsonl_output.strip():
            return []
        findings: list[dict[str, Any]] = []

        for line in jsonl_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            name = record.get("name", "unknown")
            domain = record.get("domain", "unknown")
            addresses = record.get("addresses", [])

            ips = [addr.get("ip") for addr in addresses if "ip" in addr]
            evidence = f"IPs: {', '.join(ips)}" if ips else "No IPs found"

            findings.append(
                {
                    "title": f"Subdomain Discovered: {name}",
                    "severity": "info",
                    "description": f"OWASP Amass discovered subdomain '{name}' associated with '{domain}'.",
                    "evidence": evidence,
                    "tool": "amass",
                    "target": name,
                    "timestamp": _now_iso(),
                },
            )

        return findings
