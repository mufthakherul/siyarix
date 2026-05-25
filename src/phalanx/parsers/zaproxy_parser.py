"""ZAP output parser — parses OWASP ZAP CLI output lines."""

from __future__ import annotations

import re
from datetime import UTC, datetime

_ALERT_RE = re.compile(r"(?i)\b(alert|risk|vulnerab|scripting|xss|sqli|injection|csrf|cross)\b|\[(high|medium|low|critical|info)\]")
_TARGET_RE = re.compile(r"(?i)\bhttps?://\S+")


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


class ZaproxyParser:
    """Parse ZAP output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        target = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            tmatch = _TARGET_RE.search(line)
            if tmatch:
                target = tmatch.group(0)

            if not _ALERT_RE.search(line):
                continue

            lowered = line.lower()
            if "high" in lowered or "critical" in lowered:
                severity = "high"
            elif "medium" in lowered:
                severity = "medium"
            elif "low" in lowered:
                severity = "low"
            else:
                severity = "info"

            findings.append(
                {
                    "title": f"ZAP alert: {line[:96]}",
                    "severity": severity,
                    "description": line,
                    "evidence": target,
                    "tool": "zaproxy",
                    "target": target,
                    "timestamp": _now_iso(),
                }
            )

        return findings
