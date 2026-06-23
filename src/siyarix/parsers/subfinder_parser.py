# SPDX-License-Identifier: AGPL-3.0-or-later

"""Subfinder output parser — parses subfinder text output."""

from __future__ import annotations

from typing import Any

from . import _now_iso


class SubfinderParser:
    """Parses Subfinder text output into finding dicts."""

    def parse(self, text_output: str) -> list[dict[str, Any]]:
        """Parse subfinder text output and return a list of finding dicts."""
        if not text_output or not text_output.strip():
            return []
        findings: list[dict[str, Any]] = []

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
                },
            )

        return findings
