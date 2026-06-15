# SPDX-License-Identifier: AGPL-3.0-or-later

"""netcat / nc output parser — parses connection, banner, listen mode, and transfer output."""

from __future__ import annotations

from . import _now_iso

import re

_BANNER_RE = re.compile(
    r"(?P<target>[\w.\-]+)(?::(?P<port>\d+))?\s*(?:is\s+)?"
    r"(?P<banner>(?:SSH[_-]?\d|HTTP|SSH|SMTP|FTP|POP3|IMAP|MySQL|PostgreSQL|"
    r"Microsoft\s+EES|[\w\-]+/\d[\w.]*|[\w\-]+\s+banner).*)",
    re.IGNORECASE,
)

_CONNECTED_RE = re.compile(
    r"(?:Connection\s+to\s+)?(?P<target>[\w.\-]+)(?::(?P<port>\d+))?\s+.*?(?:open|connected|succeeded|accepted)",
    re.IGNORECASE,
)

_REFUSED_RE = re.compile(
    r"(?:Connection\s+)?(?:refused|closed|timed?\s*out|timeout|unreachable|failed)\s*(?:(?:to|on)\s+)?(?P<target>[\w.\-]+)(?::(?P<port>\d+))?",
    re.IGNORECASE,
)

_LISTEN_RE = re.compile(
    r"(?:listening|listen|listening\s+on|Connection\s+received|connect\s+from)\s*[:\s]+(?P<target>[\w.\-]+)(?::(?P<port>\d+))?",
    re.IGNORECASE,
)

_TRANSFER_RE = re.compile(
    r"(?P<size>\d+)\s+(?:bytes\s+)?(?:received|sent|transferred)",
    re.IGNORECASE,
)

_SUMMARY_RE = re.compile(
    r"(?:sent|received|transferred)\s+(\d+)\s+bytes",
    re.IGNORECASE,
)


class NetcatParser:
    """Parse netcat/nc output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        total_bytes = 0

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            m = _SUMMARY_RE.search(line)
            if m:
                total_bytes += int(m.group(1))
                continue

            m = _REFUSED_RE.search(line)
            if m:
                target = m.group("target")
                port = m.group("port") or "unknown"
                key = f"refused:{target}:{port}"
                if key not in seen:
                    seen.add(key)
                    if "time" in line.lower() and "out" in line.lower():
                        desc = f"netcat connection to {target}:{port} timed out"
                    elif "refused" in line.lower():
                        desc = f"netcat connection to {target}:{port} was refused — port likely closed or filtered"
                    else:
                        desc = f"netcat connection to {target}:{port} failed"
                    findings.append({
                        "title": f"Port closed/filtered: {target}:{port}",
                        "severity": "info",
                        "description": desc,
                        "evidence": raw,
                        "tool": "netcat",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _LISTEN_RE.search(line)
            if m:
                target = m.group("target")
                port = m.group("port") or "unknown"
                key = f"listen:{target}:{port}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Connection received: {target}:{port}",
                        "severity": "medium",
                        "description": f"netcat received connection from {target}:{port} in listen mode",
                        "evidence": raw,
                        "tool": "netcat",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _BANNER_RE.search(line)
            if m:
                target = m.group("target")
                port = m.group("port") or "unknown"
                banner = m.group("banner")
                key = f"banner:{target}:{port}:{banner[:30]}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Service banner: {banner.split()[0] if banner else 'unknown'}",
                        "severity": "info",
                        "description": f"Banner grabbed from {target}:{port}: {banner}",
                        "evidence": raw,
                        "tool": "netcat",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _CONNECTED_RE.match(line)
            if m:
                target = m.group("target")
                port = m.group("port") or "unknown"
                key = f"connected:{target}:{port}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Port open: {target}:{port}",
                        "severity": "medium",
                        "description": f"netcat successfully connected to {target}:{port}",
                        "evidence": raw,
                        "tool": "netcat",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _TRANSFER_RE.search(line)
            if m:
                size = m.group("size")
                key = f"transfer:{size}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Data transfer: {size} bytes",
                        "severity": "info",
                        "description": f"netcat transferred {size} bytes",
                        "evidence": raw,
                        "tool": "netcat",
                        "target": "unknown",
                        "timestamp": _now_iso(),
                    })

        if total_bytes:
            key = "summary:total-transfer"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"netcat total: {total_bytes} bytes",
                    "severity": "info",
                    "description": f"netcat total data transfer: {total_bytes} bytes",
                    "evidence": f"Total: {total_bytes} bytes",
                    "tool": "netcat",
                    "target": "unknown",
                    "timestamp": _now_iso(),
                })

        return findings
