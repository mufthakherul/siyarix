# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hydra output parser — parses hydra text output for credential findings."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_CRED_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s*host:\s*(?P<host>\S+)\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)",
    re.IGNORECASE,
)


class HydraParser:
    """Parse hydra output into normalized credential finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _CRED_RE.search(line)
            if not m:
                continue
            host = m.group("host")
            login = m.group("login")
            password = m.group("password")
            service = m.group("service")
            port = m.group("port")
            findings.append(
                {
                    "title": f"Weak credentials discovered for {service}",
                    "severity": "critical",
                    "description": f"hydra found valid credentials for {service} on {host}:{port}.",
                    "evidence": f"{host}:{port} login={login} password={password}",
                    "tool": "hydra",
                    "target": host,
                    "timestamp": _now_iso(),
                },
            )
        return findings
