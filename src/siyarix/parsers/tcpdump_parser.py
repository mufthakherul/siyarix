# SPDX-License-Identifier: AGPL-3.0-or-later

"""tcpdump output parser — parses packet-capture text output (ARP, DNS, ICMP, TCP, UDP, IP)."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_PACKET_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<src>\S+)\s*>\s*(?P<dst>\S+)\s*:?"
    r"(?:\s+(?P<detail>.*))?",
)

_ARP_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"ARP,\s+(?P<op>Request|Reply|Gratuitous|Probe)\s+"
    r"(?:who-has\s+)?(?P<target>\S+)\s+"
    r"(?:tell|say|is-at)\s+(?P<sender>\S+)",
)

_DNS_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<src>\S+)\s*>\s*(?P<dst>\S+)\s*:?"
    r"\s+(?P<dns_op>\d+)\s+[A-Z]+\??\s+(?P<query>\S+)",
)

_ICMP_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<src>\S+)\s*>\s*(?P<dst>\S+)\s*:?"
    r"\s+ICMP\s+(?P<icmp_type>\w[\w\s]*)",
    re.IGNORECASE,
)

_TCP_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<src>\S+)\s*>\s*(?P<dst>\S+)\s*:?"
    r"\s+Flags\s+\[(?P<flags>[^\]]+)\]",
    re.IGNORECASE,
)

_DHCP_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<src>\S+)\s*>\s*(?P<dst>\S+)\s*:?"
    r"\s+DHCP\s+(?P<dhcp_type>\w+)",
    re.IGNORECASE,
)

_SUMMARY_RE = re.compile(
    r"(?:packets?\s+(?:captured|received|drops?)|received\s+by\s+filter)",
    re.IGNORECASE,
)


class TcpdumpParser:
    """Parse tcpdump text output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        summary_lines: list[str] = []

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            if _SUMMARY_RE.search(line):
                summary_lines.append(line)
                continue

            m = _ARP_RE.search(line)
            if m:
                key = f"arp:{m.group('target')}:{m.group('sender')}:{m.group('op')}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"ARP {m.group('op')}: {m.group('target')}",
                            "severity": "medium"
                            if m.group("op") in ("Gratuitous", "Probe")
                            else "info",
                            "description": f"ARP {m.group('op').lower()} observed for {m.group('target')} from {m.group('sender')}.",
                            "evidence": raw,
                            "tool": "tcpdump",
                            "target": m.group("target"),
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _ICMP_RE.search(line)
            if m:
                key = f"icmp:{m.group('src')}:{m.group('dst')}:{m.group('icmp_type').strip()}"
                if key not in seen:
                    seen.add(key)
                    icmp_type = m.group("icmp_type").strip().lower()
                    if any(
                        t in icmp_type
                        for t in ("redirect", "unreach", "time exceed", "parameter problem")
                    ):
                        severity = "medium"
                    elif any(t in icmp_type for t in ("echo request", "echo reply")):
                        severity = "low"
                    else:
                        severity = "info"
                    findings.append(
                        {
                            "title": f"ICMP {m.group('icmp_type').strip()}",
                            "severity": severity,
                            "description": f"ICMP {m.group('icmp_type').strip()} from {m.group('src')} to {m.group('dst')}.",
                            "evidence": raw,
                            "tool": "tcpdump",
                            "target": m.group("dst"),
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _TCP_RE.search(line)
            if m:
                key = f"tcp:{m.group('src')}:{m.group('dst')}:{m.group('flags')}"
                if key not in seen:
                    seen.add(key)
                    flags = m.group("flags").upper()
                    flag_desc = []
                    if "S" in flags and "A" not in flags:
                        flag_desc.append("SYN")
                    if "S" in flags and "A" in flags:
                        flag_desc.append("SYN-ACK")
                    if "A" in flags and "S" not in flags:
                        flag_desc.append("ACK")
                    if "F" in flags:
                        flag_desc.append("FIN")
                    if "R" in flags:
                        flag_desc.append("RST")
                    if "P" in flags:
                        flag_desc.append("PSH")
                    if "U" in flags:
                        flag_desc.append("URG")
                    desc = f"TCP {'|'.join(flag_desc) if flag_desc else flags} from {m.group('src')} to {m.group('dst')}"
                    findings.append(
                        {
                            "title": f"TCP packet: {m.group('src')} -> {m.group('dst')} ({','.join(flag_desc) if flag_desc else flags})",
                            "severity": "info",
                            "description": desc,
                            "evidence": raw,
                            "tool": "tcpdump",
                            "target": m.group("dst"),
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _DHCP_RE.search(line)
            if m:
                key = f"dhcp:{m.group('src')}:{m.group('dst')}:{m.group('dhcp_type')}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"DHCP {m.group('dhcp_type')}",
                            "severity": "info",
                            "description": f"DHCP {m.group('dhcp_type')} from {m.group('src')} to {m.group('dst')}.",
                            "evidence": raw,
                            "tool": "tcpdump",
                            "target": m.group("dst"),
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _DNS_RE.search(line)
            if m:
                key = f"dns:{m.group('query')}:{m.group('src')}:{m.group('dst')}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"DNS query: {m.group('query')}",
                            "severity": "info",
                            "description": f"DNS {m.group('dns_op')} query for {m.group('query')} from {m.group('src')} to {m.group('dst')}.",
                            "evidence": raw,
                            "tool": "tcpdump",
                            "target": m.group("query"),
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _PACKET_RE.match(line)
            if not m:
                continue

            proto = m.group("proto") or "IP"
            key = f"packet:{m.group('src')}:{m.group('dst')}:{proto}:{m.group('time')}"
            if key not in seen:
                seen.add(key)
                detail = m.group("detail") or ""
                desc = f"Captured {proto} packet from {m.group('src')} to {m.group('dst')}"
                if detail:
                    desc += f": {detail[:80]}"
                findings.append(
                    {
                        "title": f"Packet: {m.group('src')} -> {m.group('dst')} ({proto})",
                        "severity": "info",
                        "description": desc,
                        "evidence": raw[:200],
                        "tool": "tcpdump",
                        "target": m.group("dst"),
                        "timestamp": _now_iso(),
                    },
                )

        if summary_lines:
            findings.append(
                {
                    "title": "tcpdump: Packet summary",
                    "severity": "info",
                    "description": "; ".join(summary_lines),
                    "evidence": " | ".join(summary_lines),
                    "tool": "tcpdump",
                    "target": "unknown",
                    "timestamp": _now_iso(),
                },
            )

        return findings
