"""John the Ripper output parser."""

from __future__ import annotations

from datetime import UTC, datetime

def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()

class JohnParser:
    """Parse john --show style lines into normalized findings."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            if line.lower().startswith(("loaded", "remaining", "session", "guesses:")):
                continue
            left, right = line.split(":", 1)
            username = left.strip()
            password = right.split(":")[0].strip()
            if not username or not password:
                continue
            findings.append(
                {
                    "title": "Cracked credential discovered (john)",
                    "severity": "high",
                    "description": "john recovered plaintext credentials from password hashes.",
                    "evidence": f"user={username} password={password}",
                    "tool": "john",
                    "target": "offline-hashset",
                    "timestamp": _now_iso(),
                }
            )
        return findings
