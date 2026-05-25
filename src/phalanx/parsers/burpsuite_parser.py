"""Burp Suite output parser."""

from __future__ import annotations

from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


class BurpsuiteParser:
    """Parse text exports/log snippets from Burp Suite into findings."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
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
                }
            )
        return findings
