# SPDX-License-Identifier: AGPL-3.0-or-later

"""DMitry output parser — parses whois/portscan/subdomain/email/banner output."""

from __future__ import annotations

from . import _now_iso

import re

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)

_DOMAIN_RE = re.compile(
    r"Domain\s+name[:\s]+(.+)",
    re.IGNORECASE,
)

_NS_RE = re.compile(
    r"Name\s+[Ss]erver[:\s]+(.+)",
    re.IGNORECASE,
)

_IP_RE = re.compile(
    r"(?P<ip>[\d.]+)\s*(?:\(?[A-Z]+\)?)?\s*$",
)

_HOST_RE = re.compile(
    r"(?:Host|Subdomain)[:\s]+(\S+)",
    re.IGNORECASE,
)

_PORTSCAN_RE = re.compile(
    r"Port\s*[:\s]*(?P<port>\d+)\s*/?\s*(?P<proto>\w+)\s*"
    r"(?P<state>open|filtered|closed)?\s*"
    r"(?P<service>[\w\-]+)?",
    re.IGNORECASE,
)

_BANNER_RE = re.compile(
    r"(?:banner|Banner|service\s*banner)[:\s]+(.+)",
    re.IGNORECASE,
)

_WHOIS_SECTION_RE = re.compile(
    r"(?:whois|Whois|WHOIS)\s+(?:record|data|lookup|information)[:\s]*",
    re.IGNORECASE,
)

_TCP_PORT_RE = re.compile(
    r"(?P<port>\d+)\s*\((?P<service>\w+)\)\s*:\s*(?P<banner>.*)",
    re.IGNORECASE,
)

_SUMMARY_RE = re.compile(
    r"(?:Found|Scanned|Total|Hosts?|Ports?)[:\s]+(\d+)",
    re.IGNORECASE,
)


class DmitryParser:
    """Parse DMitry output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        domain = "unknown"

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            if _WHOIS_SECTION_RE.search(line):
                continue

            m = _DOMAIN_RE.match(line)
            if m:
                domain = m.group(1).strip()
                continue

            # Port scan line: e.g. "Port 80/tcp open http"
            m = _PORTSCAN_RE.match(line)
            if m:
                port = m.group("port")
                proto = m.group("proto") or "tcp"
                state = m.group("state") or "open"
                service = m.group("service") or ""
                key = f"port:{port}:{proto}:{state}"
                if key not in seen:
                    seen.add(key)
                    sev = "medium" if state.lower() == "open" else "info"
                    findings.append(
                        {
                            "title": f"Port {port}/{proto} ({state})",
                            "severity": sev,
                            "description": f"DMitry discovered {state} port {port}/{proto} on {domain}"
                            + (f" - {service}" if service else ""),
                            "evidence": raw,
                            "tool": "dmitry",
                            "target": domain,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            # TCP port with banner: e.g. "80 (http): Server: Apache/2.4"
            m = _TCP_PORT_RE.match(line)
            if m:
                key = f"tcp-banner:{m.group('port')}:{m.group('service')}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Banner: {m.group('port')}/{m.group('service')}",
                            "severity": "info",
                            "description": f"DMitry grabbed banner from port {m.group('port')} ({m.group('service')}) on {domain}",
                            "evidence": raw,
                            "tool": "dmitry",
                            "target": domain,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _BANNER_RE.search(line)
            if m:
                banner_text = m.group(1).strip()
                key = f"banner:{banner_text[:40]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Service banner: {banner_text[:40]}",
                            "severity": "info",
                            "description": f"DMitry discovered banner on {domain}: {banner_text}",
                            "evidence": raw,
                            "tool": "dmitry",
                            "target": domain,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _NS_RE.match(line)
            if m:
                ns = m.group(1).strip()
                key = f"ns:{ns}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Name server: {ns}",
                            "severity": "low",
                            "description": f"DMitry discovered name server {ns} for {domain}",
                            "evidence": raw,
                            "tool": "dmitry",
                            "target": domain,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            emails = _EMAIL_RE.findall(line)
            for email in emails:
                key = f"email:{email}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Email: {email}",
                            "severity": "medium",
                            "description": f"DMitry discovered email {email} associated with {domain}",
                            "evidence": email,
                            "tool": "dmitry",
                            "target": email,
                            "timestamp": _now_iso(),
                        }
                    )

            m = _HOST_RE.match(line)
            if m:
                host = m.group(1)
                key = f"host:{host}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Host: {host}",
                            "severity": "info",
                            "description": f"DMitry discovered host {host} for {domain}",
                            "evidence": raw,
                            "tool": "dmitry",
                            "target": host,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _IP_RE.match(line)
            if m and len(line.split()) <= 3:
                ip = m.group("ip")
                key = f"ip:{ip}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"IP address: {ip}",
                            "severity": "info",
                            "description": f"DMitry discovered IP {ip}",
                            "evidence": raw,
                            "tool": "dmitry",
                            "target": ip,
                            "timestamp": _now_iso(),
                        }
                    )

        return findings
