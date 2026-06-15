# SPDX-License-Identifier: AGPL-3.0-or-later

"""dnsmap output parser — parses DNS mapping results (text + CSV)."""

from __future__ import annotations

from . import _now_iso

import csv
import io
import re

_FIND_RE = re.compile(
    r"(?:found|discovered)\s*(?:sub)?domain\s*[:\s]\s*(?P<domain>\S+)"
    r"(?:\s*[\(\[]?(?:IP|ip):\s*(?P<ip>[\d.]+)[\)\]]?)?",
    re.IGNORECASE,
)

_PAREN_IP_RE = re.compile(
    r"(?P<domain>[a-zA-Z0-9][\w.\-]*[a-zA-Z0-9])\s*\((?P<ip>[\d.]+)\)",
)

_IP_RE = re.compile(
    r"(?P<domain>\S+)\s+#\s+(?P<ip>[\d.]+)",
)

_CSV_DOMAIN_RE = re.compile(
    r"(?P<domain>[a-zA-Z0-9][\w.\-]*[a-zA-Z0-9])\s*[,;]\s*(?P<ip>[\d.]+)",
)

_IP_SEVERITY = {
    "10.": "low",
    "172.16.": "low",
    "172.17.": "low",
    "172.18.": "low",
    "172.19.": "low",
    "172.20.": "low",
    "172.21.": "low",
    "172.22.": "low",
    "172.23.": "low",
    "172.24.": "low",
    "172.25.": "low",
    "172.26.": "low",
    "172.27.": "low",
    "172.28.": "low",
    "172.29.": "low",
    "172.30.": "low",
    "172.31.": "low",
    "192.168.": "low",
    "127.": "low",
}


def _ip_severity(ip: str) -> str:
    for prefix in _IP_SEVERITY:
        if ip.startswith(prefix):
            return _IP_SEVERITY[prefix]
    return "info"


class DnsmapParser:
    """Parse dnsmap output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        trimmed = output.strip()

        if not trimmed:
            return findings

        # Try CSV format
        first_line = trimmed.splitlines()[0] if trimmed.splitlines() else ""
        if "domain" in first_line.lower() and ("ip" in first_line.lower() or "address" in first_line.lower()):
            try:
                reader = csv.DictReader(io.StringIO(trimmed))
                for row in reader:
                    domain = row.get("domain", row.get("host", ""))
                    ip = row.get("ip", row.get("address", row.get("IP", "")))
                    if domain and domain not in seen:
                        seen.add(domain)
                        findings.append({
                            "title": f"Discovered subdomain: {domain}",
                            "severity": _ip_severity(ip) if ip else "info",
                            "description": f"dnsmap discovered subdomain {domain}" + (f" with IP {ip}" if ip else ""),
                            "evidence": f"{domain} -> {ip}" if ip else domain,
                            "tool": "dnsmap",
                            "target": domain,
                            "timestamp": _now_iso(),
                        })
                if findings:
                    return findings
            except Exception:
                pass

        # Try CSV domain,ip lines
        for line in trimmed.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _CSV_DOMAIN_RE.match(line)
            if m:
                domain = m.group("domain")
                ip = m.group("ip")
                if domain in seen:
                    continue
                seen.add(domain)
                findings.append({
                    "title": f"Discovered subdomain: {domain}",
                    "severity": _ip_severity(ip),
                    "description": f"dnsmap discovered subdomain {domain} with IP {ip}",
                    "evidence": f"{domain} -> {ip}",
                    "tool": "dnsmap",
                    "target": domain,
                    "timestamp": _now_iso(),
                })
                continue

            m = _FIND_RE.search(line)
            if m:
                domain = m.group("domain")
                if domain in seen:
                    continue
                seen.add(domain)
                ip = m.group("ip") or ""
                findings.append({
                    "title": f"Discovered subdomain: {domain}",
                    "severity": _ip_severity(ip) if ip else "info",
                    "description": f"dnsmap discovered subdomain {domain}" + (f" with IP {ip}" if ip else ""),
                    "evidence": line,
                    "tool": "dnsmap",
                    "target": domain,
                    "timestamp": _now_iso(),
                })
                continue

            mp = _PAREN_IP_RE.match(line)
            if mp:
                domain = mp.group("domain")
                if domain in seen:
                    continue
                seen.add(domain)
                ip = mp.group("ip")
                findings.append({
                    "title": f"Discovered subdomain: {domain}",
                    "severity": _ip_severity(ip),
                    "description": f"dnsmap mapped {domain} to {ip}",
                    "evidence": f"{domain} -> {ip}",
                    "tool": "dnsmap",
                    "target": domain,
                    "timestamp": _now_iso(),
                })
                continue

            m2 = _IP_RE.match(line)
            if m2:
                domain = m2.group("domain")
                if domain in seen:
                    continue
                seen.add(domain)
                ip = m2.group("ip")
                findings.append({
                    "title": f"Subdomain: {domain}",
                    "severity": _ip_severity(ip),
                    "description": f"dnsmap mapped {domain} to {ip}",
                    "evidence": f"{domain} -> {ip}",
                    "tool": "dnsmap",
                    "target": domain,
                    "timestamp": _now_iso(),
                })

        return findings
