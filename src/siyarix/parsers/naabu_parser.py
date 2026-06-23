# SPDX-License-Identifier: AGPL-3.0-or-later

"""Naabu output parser — parses Naabu port scanning JSON/text output."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_TCP_PORT_RE = re.compile(
    r"(?P<host>[\d.]+|[\w.\-]+)\s*[:\]]+(?P<port>\d+)(?::(?P<proto>\w+))?",
)

_HOST_RE = re.compile(
    r"(?:host|ip)[:\s]+(?P<host>\S+)",
    re.IGNORECASE,
)


_PORT_SEVERITY: dict[int, str] = {
    21: "medium",
    22: "low",
    23: "high",
    25: "medium",
    80: "info",
    443: "info",
    445: "high",
    1433: "high",
    1521: "high",
    3306: "medium",
    3389: "high",
    5432: "medium",
    5900: "high",
    6379: "high",
    8080: "info",
    27017: "high",
}


def _severity_for_port(port: int) -> str:
    return _PORT_SEVERITY.get(port, "info")


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    return stripped.splitlines()[0].strip().startswith(("[", "{"))


class NaabuParser:
    """Parse naabu output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        if _looks_like_json(output):
            try:
                return self._parse_json(output)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        return self._parse_text(output)

    def _parse_json(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError, TypeError):
                return []
        records = data if isinstance(data, list) else [data]

        for record in records:
            host = record.get("host", record.get("ip", "unknown"))
            port_num = int(record.get("port", 0))
            proto = record.get("protocol", "tcp")
            service = record.get("service", "")
            dedup_key = f"{host}:{port_num}/{proto}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            severity = _severity_for_port(port_num)
            desc = f"Naabu discovered open port {port_num}/{proto} on {host}"
            evidence = f"Open port {port_num}/{proto} on {host}"
            if service:
                desc += f" service: {service}"
                evidence += f"; service:{service}"
            findings.append(
                {
                    "title": f"Open port {port_num}/{proto}",
                    "severity": severity,
                    "description": desc,
                    "evidence": evidence,
                    "tool": "naabu",
                    "target": host,
                    "timestamp": _now_iso(),
                },
            )
        return findings

    def _parse_text(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _HOST_RE.search(line)
            if m:
                m.group("host")
                continue

            m = _TCP_PORT_RE.search(line)
            if m:
                port_num = int(m.group("port"))
                proto = m.group("proto") or "tcp"
                host_found = m.group("host")
                dedup_key = f"{host_found}:{port_num}/{proto}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _severity_for_port(port_num)
                findings.append(
                    {
                        "title": f"Open port {port_num}/{proto}",
                        "severity": severity,
                        "description": f"Naabu discovered open port {port_num}/{proto} on {host_found}",
                        "evidence": f"Open port {port_num}/{proto} on {host_found}",
                        "tool": "naabu",
                        "target": host_found,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
