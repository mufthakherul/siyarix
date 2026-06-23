# SPDX-License-Identifier: AGPL-3.0-or-later

"""Burp Suite output parser."""

from __future__ import annotations

from typing import Any

from . import _now_iso


class BurpsuiteParser:
    """Parse text exports/log snippets from Burp Suite into findings."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            lowered = line.lower()
            if (
                "issue:" not in lowered
                and "severity:" not in lowered
                and "confidence:" not in lowered
            ):
                continue
            if "severity: high" in lowered:
                severity = "high"
            elif "severity: medium" in lowered:
                severity = "medium"
            elif "severity: low" in lowered:
                severity = "low"
            else:
                severity = "info"
            findings.append(
                {
                    "title": f"Burp finding: {line[:90]}",
                    "severity": severity,
                    "description": line,
                    "evidence": line,
                    "tool": "burpsuite",
                    "target": "web-target",
                    "timestamp": _now_iso(),
                },
            )
        return findings
