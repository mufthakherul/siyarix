"""Subfinder output parser — parses subfinder text output."""

from __future__ import annotations

from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


class SubfinderParser:
    """Parses Subfinder text output into finding dicts."""

    def parse(self, text_output: str) -> list[dict]:
        """Parse subfinder text output and return a list of finding dicts."""
        findings: list[dict] = []

        for line in text_output.splitlines():
            line = line.strip()
            # Subfinder often outputs subdomains directly, one per line.
            # Skip empty lines or banner lines (often start with brackets or are very long)
            if not line or " " in line or line.startswith("["):
                continue

            findings.append(
                {
                    "title": f"Subdomain Discovered: {line}",
                    "severity": "info",
                    "description": f"Subfinder discovered subdomain: {line}",
                    "evidence": line,
                    "tool": "subfinder",
                    "target": line,
                    "timestamp": _now_iso(),
                }
            )

        return findings
