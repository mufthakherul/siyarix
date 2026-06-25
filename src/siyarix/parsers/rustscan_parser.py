# SPDX-License-Identifier: AGPL-3.0-or-later

"""RustScan output parser — parses RustScan port scanning JSON/text output."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_TEXT_PORT_RE = re.compile(
    r"(?:Open|Port)\s+(?P<port>\d+)\s*[:\-/]\s*(?P<proto>\w+)?\s*(?P<state>\S+)?",
    re.IGNORECASE,
)

_HOST_RE = re.compile(
    r"(?:Host|Target)[:\s]+(?P<host>\S+)",
    re.IGNORECASE,
)

_GREPPABLE_RE = re.compile(
    r"(?P<host>\S+):(?P<port>\d+)(?::(?P<proto>\w+))?",
)


_OPEN_HOST_PORT_RE = re.compile(
    r"Open\s+(?P<host>\S+):(?P<port>\d+)",
    re.IGNORECASE,
)

_BANNER_RE = re.compile(
    r"(?:Banner|banner)[:\s]+(?P<banner>.+)",
    re.IGNORECASE,
)

_SERVICE_RE = re.compile(
    r"(?:Service|service)[:\s]+(?P<service>.+)",
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

_GREPPABLE_SEVERITY_OVERRIDE: dict[str, str] = {}


def _severity_for_port(port: int) -> str:
    return _PORT_SEVERITY.get(port, "info")


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    return stripped.splitlines()[0].strip().startswith(("[", "{"))


class RustscanParser:
    """Parse RustScan output into normalized finding dictionaries."""

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
            ports = record.get("ports", [])
            service_detected = record.get("service", "")
            if isinstance(ports, list):
                for p in ports:
                    if isinstance(p, dict):
                        port_num = int(p.get("port", 0))
                        proto = p.get("protocol", "tcp")
                        port_service = p.get("service", service_detected)
                    else:
                        port_num = int(p)
                        proto = "tcp"
                        port_service = ""
                    dedup_key = f"{host}:{port_num}/{proto}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    severity = _severity_for_port(port_num)
                    desc = f"RustScan discovered open port {port_num}/{proto} on {host}"
                    evidence = f"{host}:{port_num}/{proto}"
                    if port_service:
                        desc += f" service: {port_service}"
                        evidence += f"; service:{port_service}"
                    findings.append(
                        {
                            "title": f"Open port {port_num}/{proto}",
                            "severity": severity,
                            "description": desc,
                            "evidence": evidence,
                            "tool": "rustscan",
                            "target": host,
                            "timestamp": _now_iso(),
                        },
                    )
        return findings

    def _parse_text(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        host = "unknown"
        banner = ""
        service = ""

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _BANNER_RE.search(line)
            if m:
                banner = m.group("banner").strip()
                continue

            m = _SERVICE_RE.search(line)
            if m:
                service = m.group("service").strip()
                continue

            m = _HOST_RE.search(line)
            if m:
                host = m.group("host")
                continue

            m = _GREPPABLE_RE.match(line)
            if m:
                host_g = m.group("host")
                port_num = int(m.group("port"))
                proto = m.group("proto") or "tcp"
                dedup_key = f"{host_g}:{port_num}/{proto}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _severity_for_port(port_num)
                desc = f"RustScan discovered open port {port_num}/{proto} on {host_g}"
                evidence = f"Open {port_num}/{proto} on {host_g}"
                if banner:
                    desc += f" banner: {banner}"
                    evidence += f"; banner:{banner}"
                if service:
                    desc += f" service: {service}"
                    evidence += f"; service:{service}"
                findings.append(
                    {
                        "title": f"Open port {port_num}/{proto}",
                        "severity": severity,
                        "description": desc,
                        "evidence": evidence,
                        "tool": "rustscan",
                        "target": host_g,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            m = _OPEN_HOST_PORT_RE.search(line)
            if m:
                host_g = m.group("host")
                port_num = int(m.group("port"))
                proto = "tcp"
                dedup_key = f"{host_g}:{port_num}/{proto}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _severity_for_port(port_num)
                desc = f"RustScan discovered open port {port_num}/{proto} on {host_g}"
                evidence = f"Open {port_num}/{proto} on {host_g}"
                findings.append(
                    {
                        "title": f"Open port {port_num}/{proto}",
                        "severity": severity,
                        "description": desc,
                        "evidence": evidence,
                        "tool": "rustscan",
                        "target": host_g,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            m = _TEXT_PORT_RE.search(line)
            if m:
                port_num = int(m.group("port"))
                proto = m.group("proto") or "tcp"
                dedup_key = f"{host}:{port_num}/{proto}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _severity_for_port(port_num)
                desc = f"RustScan discovered open port {port_num}/{proto} on {host}"
                evidence = f"Open {port_num}/{proto} on {host}"
                if banner:
                    desc += f" banner: {banner}"
                    evidence += f"; banner:{banner}"
                if service:
                    desc += f" service: {service}"
                    evidence += f"; service:{service}"
                findings.append(
                    {
                        "title": f"Open port {port_num}/{proto}",
                        "severity": severity,
                        "description": desc,
                        "evidence": evidence,
                        "tool": "rustscan",
                        "target": host,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
