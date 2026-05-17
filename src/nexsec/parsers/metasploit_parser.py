"""Metasploit console output parser."""

from __future__ import annotations

from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


class MetasploitParser:
    """Parse msfconsole output into normalized findings."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            lowered = line.lower()
            if "meterpreter session" in lowered and "opened" in lowered:
                severity = "critical"
            elif lowered.startswith("[+]") or "exploit completed" in lowered:
                severity = "high"
            elif lowered.startswith("[-]") or "failed" in lowered:
                severity = "medium"
            else:
                continue
            findings.append(
                {
                    "title": f"Metasploit event: {line[:90]}",
                    "severity": severity,
                    "description": line,
                    "evidence": line,
                    "tool": "metasploit",
                    "target": "runtime-target",
                    "timestamp": _now_iso(),
                }
            )
        return findings
