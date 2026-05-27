"""Aircrack-ng output parser — wireless assessment results."""

from __future__ import annotations

from . import _now_iso

import re


_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*([^\]]+)\s*\]", re.IGNORECASE)


class AircrackParser:
    """Parse aircrack-ng output into normalized findings."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            lowered = line.lower()
            km = _KEY_FOUND_RE.search(line)
            if km:
                findings.append(
                    {
                        "title": "WPA key cracked with aircrack-ng",
                        "severity": "critical",
                        "description": f"WPA key recovered: {km.group(1)}",
                        "evidence": line,
                        "tool": "aircrack-ng",
                        "target": "wireless",
                        "timestamp": _now_iso(),
                    }
                )
            elif "handshake" in lowered and "captured" in lowered:
                findings.append(
                    {
                        "title": "WPA handshake captured",
                        "severity": "high",
                        "description": line,
                        "evidence": line,
                        "tool": "aircrack-ng",
                        "target": "wireless",
                        "timestamp": _now_iso(),
                    }
                )
            elif "deauth" in lowered or "deauthenticating" in lowered:
                findings.append(
                    {
                        "title": "Aircrack-ng deauth attack",
                        "severity": "high",
                        "description": line,
                        "evidence": line,
                        "tool": "aircrack-ng",
                        "target": "wireless",
                        "timestamp": _now_iso(),
                    }
                )
        return findings
