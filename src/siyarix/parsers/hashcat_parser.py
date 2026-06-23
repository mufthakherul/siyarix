# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hashcat output parser."""

from __future__ import annotations

from typing import Any

from . import _now_iso


class HashcatParser:
    """Parse hashcat --show style lines into normalized findings."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            if line.lower().startswith(("session", "status", "speed", "progress", "hash.mode")):
                continue
            hash_part, plain = line.rsplit(":", 1)
            if not hash_part or not plain:
                continue
            findings.append(
                {
                    "title": "Recovered password hash plaintext (hashcat)",
                    "severity": "high",
                    "description": "hashcat produced plaintext output for a target hash.",
                    "evidence": f"hash={hash_part[:24]}... plaintext={plain}",
                    "tool": "hashcat",
                    "target": "offline-hashset",
                    "timestamp": _now_iso(),
                },
            )
        return findings
