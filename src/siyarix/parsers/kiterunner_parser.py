# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations
import json
from typing import Any
from . import BaseParser, build_finding

class KiterunnerParser(BaseParser):
    """Parses Kiterunner API discovery output."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    url = data.get("URL", "")
                    status = data.get("Status", 0)
                    findings.append(build_finding(
                        title=f"Kiterunner API Endpoint: {url}",
                        severity="info",
                        description=f"Found API endpoint {url} returning {status}",
                        evidence=line,
                        tool="kiterunner",
                        target=url,
                    ))
                except json.JSONDecodeError:
                    pass
            elif "GET" in line or "POST" in line:
                parts = line.split()
                if len(parts) >= 2:
                    findings.append(build_finding(
                        title=f"Kiterunner Route: {parts[0]} {parts[1]}",
                        severity="info",
                        description=line,
                        evidence=line,
                        tool="kiterunner",
                        target=parts[1],
                    ))
        return findings
