# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from typing import Any

from . import BaseParser, build_finding


class ZmapParser(BaseParser):
    """Parses Zmap raw IP output or CSV."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("saddr"):
                continue
            findings.append(
                build_finding(
                    title=f"Zmap Host Alive: {line}",
                    severity="info",
                    description=f"Host responded to zmap probe: {line}",
                    evidence=line,
                    tool="zmap",
                    target=line,
                ),
            )
        return findings
