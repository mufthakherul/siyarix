# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations
from typing import Any
from . import BaseParser, build_finding


class WaybackurlsParser(BaseParser):
    """Parses Waybackurls raw URL list output."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        findings = []
        urls = set()
        for line in output.splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            if line not in urls:
                urls.add(line)
                findings.append(
                    build_finding(
                        title="Wayback Machine URL",
                        severity="info",
                        description=f"Discovered historical URL: {line}",
                        evidence=line,
                        tool="waybackurls",
                        target=line,
                    )
                )
        return findings
