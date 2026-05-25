"""Ettercap output parser — MITM and packet sniffing results."""

from __future__ import annotations

from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


class EttercapParser:
    """Parse ettercap output into normalized findings."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            lowered = line.lower()
            if "password" in lowered or "pass:" in lowered:
                findings.append(
                    {
                        "title": "Ettercap captured credentials",
                        "severity": "critical",
                        "description": line,
                        "evidence": line,
                        "tool": "ettercap",
                        "target": "network",
                        "timestamp": _now_iso(),
                    }
                )
            elif "ssl strip" in lowered or "https" in lowered:
                findings.append(
                    {
                        "title": "Ettercap SSL stripping detected",
                        "severity": "high",
                        "description": line,
                        "evidence": line,
                        "tool": "ettercap",
                        "target": "network",
                        "timestamp": _now_iso(),
                    }
                )
            elif "host" in lowered and ("added" in lowered or "detected" in lowered):
                findings.append(
                    {
                        "title": "Ettercap host discovery",
                        "severity": "medium",
                        "description": line,
                        "evidence": line,
                        "tool": "ettercap",
                        "target": "network",
                        "timestamp": _now_iso(),
                    }
                )
        return findings
