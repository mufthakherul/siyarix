# SPDX-License-Identifier: AGPL-3.0-or-later

"""masscan output parser — parses masscan text output lines."""

from __future__ import annotations

from . import _now_iso

import re

_OPEN_RE = re.compile(r"^Discovered open port (?P<port>\d+)/(?P<proto>\w+) on (?P<host>\S+)")


class MasscanParser:
    """Parse masscan output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _OPEN_RE.match(line)
            if not m:
                continue
            port = m.group("port")
            proto = m.group("proto")
            host = m.group("host")
            findings.append(
                {
                    "title": f"Open port discovered: {port}/{proto}",
                    "severity": "info",
                    "description": f"masscan discovered an open {proto.upper()} port ({port}) on host {host}.",
                    "evidence": f"{host}:{port}/{proto}",
                    "tool": "masscan",
                    "target": host,
                    "timestamp": _now_iso(),
                }
            )
        return findings
