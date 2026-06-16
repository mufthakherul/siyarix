# SPDX-License-Identifier: AGPL-3.0-or-later

"""theHarvester output parser — parses OSINT email/subdomain/host text and JSON output."""

from __future__ import annotations

from . import _now_iso

import json
import re

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)

_HOST_RE = re.compile(
    r"(?:host|subdomain|domain|server)[:\s]*(?P<host>\S+)",
    re.IGNORECASE,
)

_IP_RE = re.compile(
    r"(?P<ip>[\d.]+(?::\d+)?)",
)

_SECTION_RE = re.compile(
    r"^[*#]+\s*(?:Emails|Hosts|IPs|Subdomains|Virtual\s+Hosts|Links|Servers|Linkedin|Twitter|Vhosts|Shodan|People)",
    re.IGNORECASE,
)

_FOUND_RE = re.compile(
    r"(?:(?P<type>Emails|Hosts|IPs|Subdomains|Users)\s+found\s*:?\s*(?P<count>\d+)|total\s+(?:emails|hosts|users)\s+found)",
    re.IGNORECASE,
)

_URL_RE = re.compile(
    r"https?://\S+",
)

_ATTRIBUTION_RE = re.compile(
    r"(?:attribution|source|search)\s*[:\s]+(.+)",
    re.IGNORECASE,
)


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    return stripped.splitlines()[0].strip().startswith(("[", "{"))


class TheharvesterParser:
    """Parse theHarvester output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        if _looks_like_json(output):
            try:
                return self._parse_json(output)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        return self._parse_text(output)

    def _parse_json(self, json_str: str) -> list[dict]:
        data = json.loads(json_str)
        findings: list[dict] = []
        seen: set[str] = set()
        domain = data.get("domain", "unknown")

        sections = {
            "emails": ("email", "medium"),
            "hosts": ("host", "info"),
            "ips": ("IP", "info"),
            "linkedin": ("LinkedIn", "info"),
            "twitter": ("Twitter", "info"),
            "vhosts": ("vhost", "info"),
            "subdomains": ("subdomain", "info"),
            "shodan": ("Shodan", "medium"),
            "people": ("person", "info"),
        }

        for section_key, (label, default_severity) in sections.items():
            items = data.get(section_key, [])
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict):
                    value = item.get("value") or item.get("host") or item.get("ip") or str(item)
                    attrib = item.get("attribution", item.get("source", ""))
                else:
                    value = str(item)
                    attrib = ""
                if not value or value in seen:
                    continue
                seen.add(value)
                desc = f"theHarvester discovered {label.lower()} {value} associated with {domain}"
                evidence = f"{label.lower()}:{value}"
                if attrib:
                    desc += f" (source: {attrib})"
                    evidence += f"; source:{attrib}"
                findings.append(
                    {
                        "title": f"{label}: {value}",
                        "severity": default_severity,
                        "description": desc,
                        "evidence": evidence,
                        "tool": "theharvester",
                        "target": value,
                        "timestamp": _now_iso(),
                    }
                )

        return findings

    def _parse_text(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        domain = "unknown"
        current_section = ""
        attribution = ""

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if "domain" in line.lower() and ":" in line:
                parts = line.split(":", 1)
                domain = parts[-1].strip()

            am = _ATTRIBUTION_RE.match(line)
            if am:
                attribution = am.group(1).strip()

            if _SECTION_RE.match(line):
                current_section = line.strip("#* ").strip().lower()
                continue

            fm = _FOUND_RE.search(line)
            if fm:
                if fm.group("type"):
                    current_section = fm.group("type").lower()
                continue

            if current_section == "emails":
                emails = _EMAIL_RE.findall(line)
                for email in emails:
                    if email in seen:
                        continue
                    seen.add(email)
                    desc = f"theHarvester discovered email address {email} associated with {domain}"
                    evidence = email
                    if attribution:
                        desc += f" (source: {attribution})"
                        evidence += f"; source:{attribution}"
                    findings.append(
                        {
                            "title": f"Email: {email}",
                            "severity": "medium",
                            "description": desc,
                            "evidence": evidence,
                            "tool": "theharvester",
                            "target": email,
                            "timestamp": _now_iso(),
                        }
                    )
            elif current_section in ("hosts", "subdomains", "virtual hosts", "vhosts"):
                hm = _HOST_RE.search(line)
                if hm:
                    host = hm.group("host")
                elif _URL_RE.match(line):
                    host = line.strip()
                elif line.startswith(("http://", "https://", "www.", "mail.")):
                    host = line.strip()
                else:
                    host = line.strip()
                if host and host not in ("", domain) and host not in seen:
                    seen.add(host)
                    desc = f"theHarvester discovered host {host} associated with {domain}"
                    evidence = host
                    if attribution:
                        desc += f" (source: {attribution})"
                        evidence += f"; source:{attribution}"
                    findings.append(
                        {
                            "title": f"Host: {host}",
                            "severity": "info",
                            "description": desc,
                            "evidence": evidence,
                            "tool": "theharvester",
                            "target": host,
                            "timestamp": _now_iso(),
                        }
                    )
            elif current_section == "ips":
                im = _IP_RE.match(line)
                if im:
                    ip = im.group("ip")
                    if ip in seen:
                        continue
                    seen.add(ip)
                    desc = f"theHarvester discovered IP {ip} associated with {domain}"
                    evidence = ip
                    if attribution:
                        desc += f" (source: {attribution})"
                        evidence += f"; source:{attribution}"
                    findings.append(
                        {
                            "title": f"IP: {ip}",
                            "severity": "info",
                            "description": desc,
                            "evidence": evidence,
                            "tool": "theharvester",
                            "target": ip,
                            "timestamp": _now_iso(),
                        }
                    )
            elif current_section in ("linkedin", "twitter", "people"):
                if line.strip() and line not in seen:
                    seen.add(line)
                    desc = f"theHarvester discovered {current_section} entry {line} associated with {domain}"
                    evidence = line
                    if attribution:
                        desc += f" (source: {attribution})"
                        evidence += f"; source:{attribution}"
                    findings.append(
                        {
                            "title": f"{current_section.capitalize()}: {line}",
                            "severity": "info",
                            "description": desc,
                            "evidence": evidence,
                            "tool": "theharvester",
                            "target": line,
                            "timestamp": _now_iso(),
                        }
                    )

        return findings
