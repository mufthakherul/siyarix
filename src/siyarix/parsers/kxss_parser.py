# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations
import re
from typing import Any
from . import BaseParser, build_finding

class KxssParser(BaseParser):
    """Parses Kxss output for unfiltered parameters."""

    _KXSS_RE = re.compile(r"URL:\s*(?P<url>\S+)\s*Param:\s*(?P<param>\S+)\s*Unfiltered:\s*\[(?P<chars>[^\]]+)\]")

    def parse(self, output: str) -> list[dict[str, Any]]:
        findings = []
        for line in output.splitlines():
            m = self._KXSS_RE.search(line)
            if m:
                url = m.group("url")
                param = m.group("param")
                chars = m.group("chars")
                findings.append(build_finding(
                    title=f"Reflective Parameter: {param}",
                    severity="medium",
                    description=f"Parameter '{param}' reflects unfiltered characters: {chars}",
                    evidence=line.strip(),
                    tool="kxss",
                    target=url,
                ))
        return findings
