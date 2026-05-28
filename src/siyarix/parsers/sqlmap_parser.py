# SPDX-License-Identifier: AGPL-3.0-or-later

"""sqlmap output parser — parses sqlmap plain-text output."""

from __future__ import annotations

from . import _now_iso

import re

_SEVERITY_BY_LEVEL = {
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "info": "info",
    "debug": "low",
}

_LINE_RE = re.compile(r"^\[(CRITICAL|ERROR|WARNING|INFO|DEBUG)\]\s+(.+)$")
_TARGET_RE = re.compile(r"target URL appears to be '(?P<url>[^']+)'")

class SqlmapParser:
    """Parse sqlmap output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        target = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            target_match = _TARGET_RE.search(line)
            if target_match:
                target = target_match.group("url")

            m = _LINE_RE.match(line)
            if not m:
                continue

            level = m.group(1).lower()
            message = m.group(2).strip()
            if message.startswith("you can find results of scanning"):
                continue

            severity = _SEVERITY_BY_LEVEL.get(level, "info")
            findings.append(
                {
                    "title": f"sqlmap {level.upper()}: {message[:96]}",
                    "severity": severity,
                    "description": message,
                    "evidence": target,
                    "tool": "sqlmap",
                    "target": target,
                    "timestamp": _now_iso(),
                }
            )

        return findings
