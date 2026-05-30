# SPDX-License-Identifier: AGPL-3.0-or-later

"""Nmap output parser — supports both XML and plain-text output."""

from __future__ import annotations

from . import _now_iso

import re
import xml.etree.ElementTree as ET  # nosec B405


# Severity mapping based on port number / service risk
_PORT_SEVERITY: dict[int, str] = {
    21: "medium",  # FTP
    22: "low",  # SSH
    23: "high",  # Telnet
    25: "medium",  # SMTP
    53: "low",  # DNS
    80: "info",  # HTTP
    110: "medium",  # POP3
    111: "medium",  # rpcbind
    135: "medium",  # MSRPC
    139: "medium",  # NetBIOS
    143: "medium",  # IMAP
    161: "medium",  # SNMP
    389: "medium",  # LDAP
    443: "info",  # HTTPS
    445: "high",  # SMB
    512: "high",  # rexec
    513: "high",  # rlogin
    514: "high",  # rsh
    1433: "high",  # MSSQL
    1521: "high",  # Oracle DB
    2049: "medium",  # NFS
    3306: "medium",  # MySQL
    3389: "high",  # RDP
    5432: "medium",  # PostgreSQL
    5900: "high",  # VNC
    6379: "high",  # Redis
    8080: "info",  # HTTP alt
    8443: "info",  # HTTPS alt
    9200: "high",  # Elasticsearch
    27017: "high",  # MongoDB
}


def _severity_for_port(port: int) -> str:
    return _PORT_SEVERITY.get(port, "info")

class NmapParser:
    """Parses nmap XML (preferred) or plain-text output into normalised finding dicts."""

    def parse(self, xml_output: str) -> list[dict]:
        """Parse *xml_output* and return a list of finding dicts.

        Falls back to text parsing if the input is not valid XML.
        """
        rust_findings = rust_parse_nmap_xml(xml_output)
        if rust_findings is not None:
            for finding in rust_findings:
                finding.setdefault("timestamp", _now_iso())
            return rust_findings
        try:
            return self._parse_xml(xml_output)
        except ET.ParseError:
            return self._parse_text(xml_output)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_xml(self, xml_str: str) -> list[dict]:
        root = ET.fromstring(xml_str)  # nosec B314
        findings: list[dict] = []

        for host in root.findall("host"):
            address_el = host.find("address")
            if address_el is None:
                continue
            target = address_el.get("addr", "unknown")

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")

                service_el = port_el.find("service")
                service_name = "unknown"
                service_version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "unknown")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    service_version = f"{product} {version}".strip()

                severity = _severity_for_port(port_num)
                description = (
                    f"Port {port_num}/{protocol} is open — service: {service_name}"
                )
                if service_version:
                    description += f" ({service_version})"

                findings.append(
                    {
                        "title": f"Open port {port_num}/{protocol} ({service_name})",
                        "severity": severity,
                        "description": description,
                        "evidence": f"{target}:{port_num}/{protocol}",
                        "tool": "nmap",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

        return findings

    def _parse_text(self, text: str) -> list[dict]:
        """Fallback plain-text parser for nmap default output."""
        findings: list[dict] = []
        current_host = "unknown"
        host_re = re.compile(r"Nmap scan report for (.+)")
        port_re = re.compile(r"(\d+)/(\w+)\s+open\s+(\S+)(.*)")

        for line in text.splitlines():
            m = host_re.search(line)
            if m:
                current_host = m.group(1).strip()
                continue
            m = port_re.match(line.strip())
            if m:
                port_num = int(m.group(1))
                protocol = m.group(2)
                service = m.group(3)
                extra = m.group(4).strip()
                severity = _severity_for_port(port_num)
                description = f"Port {port_num}/{protocol} is open — service: {service}"
                if extra:
                    description += f" {extra}"
                findings.append(
                    {
                        "title": f"Open port {port_num}/{protocol} ({service})",
                        "severity": severity,
                        "description": description,
                        "evidence": f"{current_host}:{port_num}/{protocol}",
                        "tool": "nmap",
                        "target": current_host,
                        "timestamp": _now_iso(),
                    }
                )
        return findings
