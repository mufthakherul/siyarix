# SPDX-License-Identifier: AGPL-3.0-or-later

"""Evil-WinRM output parser — extracts connection confirmation, WinRM banner, and PS remoting session info."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_CONNECT_RE = re.compile(
    r"(?:Connecting|Established|Connected|Session)\s+.*?(?:to|with|established)", re.IGNORECASE,
)
_BANNER_RE = re.compile(r"(?:Evil.WinRM|WinRM|PS\s+session|PowerShell\s+session)", re.IGNORECASE)
_IP_PORT_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?")
_USER_RE = re.compile(r"(?:user|username)[:\s]+(\S+)", re.IGNORECASE)
_HOST_RE = re.compile(r"(?:host|hostname|remote)[:\s]+(\S+)", re.IGNORECASE)
_ERROR_RE = re.compile(r"(?:error|failed|denied|refused)", re.IGNORECASE)
_SUCCESS_RE = re.compile(r"(?:success|authenticated|logged)", re.IGNORECASE)

_JSON_RE = re.compile(r"^\s*[{\[]")


class EvilWinrmParser:
    """Parse evil-winrm output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        target = "unknown"
        username = "unknown"
        stripped = output.strip()
        if not stripped:
            return findings

        seen_hosts: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                import json

                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    host = item.get("host", item.get("ip", "unknown"))
                    user = item.get("username", item.get("user", ""))
                    if host and host != "unknown":
                        dedup_key = f"session|{host}"
                        if dedup_key not in seen_hosts:
                            seen_hosts.add(dedup_key)
                            findings.append(
                                {
                                    "title": "Evil-WinRM: Session established",
                                    "severity": "critical",
                                    "description": f"Evil-WinRM session established on {host} as {user}",
                                    "evidence": json.dumps(item),
                                    "tool": "evil_winrm",
                                    "target": host,
                                    "timestamp": _now_iso(),
                                },
                            )
                return findings
            except json.JSONDecodeError:
                pass

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            m = _BANNER_RE.search(line_stripped)
            if m:
                description = "Evil-WinRM session established"
                ip_m = _IP_PORT_RE.search(line_stripped)
                if ip_m:
                    target = ip_m.group(1)
                u_m = _USER_RE.search(line_stripped)
                if u_m:
                    username = u_m.group(1)
                    description += f" as {username}"

                dedup_key = f"session|{target}"
                if dedup_key not in seen_hosts:
                    seen_hosts.add(dedup_key)
                    findings.append(
                        {
                            "title": "Evil-WinRM: Session established",
                            "severity": "critical",
                            "description": description,
                            "evidence": line_stripped,
                            "tool": "evil_winrm",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _CONNECT_RE.search(line_stripped)
            if m:
                description = "Evil-WinRM connection attempt"
                ip_m = _IP_PORT_RE.search(line_stripped)
                if ip_m:
                    target = ip_m.group(1)

                if _ERROR_RE.search(line_stripped):
                    severity = "info"
                    description = "Evil-WinRM connection failed"
                elif _SUCCESS_RE.search(line_stripped):
                    severity = "critical"
                else:
                    severity = "high"

                dedup_key = f"connect|{target}"
                if dedup_key not in seen_hosts:
                    seen_hosts.add(dedup_key)
                    findings.append(
                        {
                            "title": "Evil-WinRM: Connection",
                            "severity": severity,
                            "description": description,
                            "evidence": line_stripped,
                            "tool": "evil_winrm",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            ip_m = _IP_PORT_RE.search(line_stripped)
            if ip_m and (
                "winrm" in line_stripped.lower()
                or "http" in line_stripped.lower()
                or "port" in line_stripped.lower()
            ):
                target = ip_m.group(1)
                findings.append(
                    {
                        "title": "Evil-WinRM: Target identified",
                        "severity": "info",
                        "description": f"WinRM target: {target}",
                        "evidence": line_stripped,
                        "tool": "evil_winrm",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
