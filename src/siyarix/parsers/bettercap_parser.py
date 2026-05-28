# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bettercap output parser — MITM attack results."""

from __future__ import annotations

import re

from . import _now_iso

_ENDPOINT_RE = re.compile(r"(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)")


class BettercapParser:
    """Parse bettercap output into normalized findings."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            lowered = line.lower()
            if "captured" in lowered and "password" in lowered:
                findings.append(
                    {
                        "title": "Bettercap captured credentials",
                        "severity": "critical",
                        "description": line,
                        "evidence": line,
                        "tool": "bettercap",
                        "target": "network",
                        "timestamp": _now_iso(),
                    }
                )
            elif "endpoint" in lowered or "new device" in lowered:
                m = _ENDPOINT_RE.search(line)
                findings.append(
                    {
                        "title": "Bettercap discovered endpoint",
                        "severity": "medium",
                        "description": line,
                        "evidence": line,
                        "tool": "bettercap",
                        "target": m.group(1) if m else "network",
                        "timestamp": _now_iso(),
                    }
                )
            elif "spoofing" in lowered or "mitm" in lowered:
                findings.append(
                    {
                        "title": "Bettercap MITM attack active",
                        "severity": "high",
                        "description": line,
                        "evidence": line,
                        "tool": "bettercap",
                        "target": "network",
                        "timestamp": _now_iso(),
                    }
                )
        return findings
