# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations
from typing import Any
from . import BaseParser, build_finding


class ParamspiderParser(BaseParser):
    """Parses Paramspider URL parameter output."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            findings.append(
                build_finding(
                    title="Paramspider Discovered Parameter",
                    severity="info",
                    description=f"Discovered URL with parameters: {line}",
                    evidence=line,
                    tool="paramspider",
                    target=line,
                )
            )
        return findings
