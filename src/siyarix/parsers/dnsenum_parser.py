# SPDX-License-Identifier: AGPL-3.0-or-later

"""dnsenum output parser — parses DNS enumeration text and CSV output."""

from __future__ import annotations

import csv
import io
import re
from typing import Any

from . import _now_iso

_HOST_RE = re.compile(
    r"(?P<host>\S+)\s+(?:IN\s+)?(?P<type>[A-Z]+)\s+(?P<value>\S.*)",
)

_SOA_RE = re.compile(
    r"SOA\s+(?P<mname>\S+)\s+(?P<rname>\S+)",
    re.IGNORECASE,
)

_SOA_DETAIL_RE = re.compile(
    r"SOA\s+(?P<mname>\S+)\s+(?P<rname>\S+)\s+(?P<serial>\d+)\s+(?P<refresh>\d+)\s+(?P<retry>\d+)\s+(?P<expire>\d+)\s+(?P<minimum>\d+)",
    re.IGNORECASE,
)

_WILDCARD_RE = re.compile(
    r"wildcard\s+(?:detected|found)",
    re.IGNORECASE,
)

_ZONE_RE = re.compile(
    r"zone\s+transfer\s+(?:attack\s+)?(?:\S+\s+)?(?:completed|successful|permitted)",
    re.IGNORECASE,
)

_BRACKET_RE = re.compile(
    r"(?P<host>[a-zA-Z0-9][\w.\-]*[a-zA-Z0-9])\s*\.+\s*\[(?P<type>[A-Z]+):\s*(?P<value>[^\]]+)\]",
)

_THREAD_RE = re.compile(
    r"(?P<thread>\d+)\s*:\s*(?P<host>\S+)\s*(?:\((?P<ip>[\d.]+)\))?",
)

_MX_RE = re.compile(
    r"(?P<host>\S+)\s+IN\s+MX\s+(?P<priority>\d+)\s+(?P<target>\S+)",
    re.IGNORECASE,
)

_NS_RE = re.compile(
    r"(?P<host>\S+)\s+IN\s+NS\s+(?P<target>\S+)",
    re.IGNORECASE,
)

_TXT_RE = re.compile(
    r"(?P<host>\S+)\s+IN\s+TXT\s+(?P<text>.+)",
    re.IGNORECASE,
)

_CNAME_RE = re.compile(
    r"(?P<host>\S+)\s+IN\s+CNAME\s+(?P<target>\S+)",
    re.IGNORECASE,
)

_THREAD_COMPLETE_RE = re.compile(
    r"(?:thread|worker)\s+\d+\s+(?:completed|finished|done)",
    re.IGNORECASE,
)


def _looks_like_csv(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    first = stripped.splitlines()[0].strip().lower()
    return "," in first and any(
        kw in first for kw in ("type", "name", "address", "target", "domain", "host")
    )


class DnsenumParser:
    """Parse dnsenum output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        if _looks_like_csv(output):
            try:
                return self._parse_csv(output)
            except (csv.Error, Exception):
                pass
        return self._parse_text(output)

    def _parse_csv(self, csv_str: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        reader = csv.DictReader(io.StringIO(csv_str))

        for row in reader:
            host = row.get("host", row.get("name", "unknown"))
            rtype = row.get("type", row.get("record_type", "A")).upper()
            value = row.get("value", row.get("address", row.get("target", "")))

            dedup_key = f"{host}:{rtype}:{value}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "info"
            if rtype in ("AXFR", "IXFR"):
                severity = "high"
            elif rtype in {"NS", "MX"}:
                severity = "low"

            findings.append(
                {
                    "title": f"DNS {rtype}: {host}",
                    "severity": severity,
                    "description": f"dnsenum discovered {rtype} record {host} -> {value}",
                    "evidence": f"{host} IN {rtype} {value}",
                    "tool": "dnsenum",
                    "target": host,
                    "timestamp": _now_iso(),
                },
            )
        return findings

    def _parse_text(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        base_domain = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if "dnsenum" in line.lower() and "domain" in line.lower():
                parts = line.rsplit(":", 1)
                if len(parts) > 1:
                    base_domain = parts[-1].strip()

            if _THREAD_COMPLETE_RE.search(line):
                tc_key = f"thread_complete:{base_domain}"
                if tc_key not in seen:
                    seen.add(tc_key)
                    findings.append(
                        {
                            "title": "dnsenum thread completed",
                            "severity": "info",
                            "description": f"dnsenum completed enumeration threads for {base_domain}",
                            "evidence": line,
                            "tool": "dnsenum",
                            "target": base_domain,
                            "timestamp": _now_iso(),
                        },
                    )

            if _WILDCARD_RE.search(line):
                wk = f"wildcard:{base_domain}"
                if wk not in seen:
                    seen.add(wk)
                    findings.append(
                        {
                            "title": "DNS wildcard detected",
                            "severity": "medium",
                            "description": f"DNS wildcard entries detected for {base_domain} — subdomain enumeration results may include false positives.",
                            "evidence": line,
                            "tool": "dnsenum",
                            "target": base_domain,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            if _ZONE_RE.search(line):
                zk = f"zone_xfer:{base_domain}"
                if zk not in seen:
                    seen.add(zk)
                    findings.append(
                        {
                            "title": "DNS zone transfer permitted",
                            "severity": "high",
                            "description": f"DNS zone transfer is permitted for {base_domain} — potential information disclosure.",
                            "evidence": line,
                            "tool": "dnsenum",
                            "target": base_domain,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            mx_m = _MX_RE.match(line)
            if mx_m:
                host = mx_m.group("host")
                target = mx_m.group("target")
                priority = mx_m.group("priority")
                dedup_key = f"MX:{host}:{target}:{priority}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"Mail server: {target}",
                        "severity": "low",
                        "description": f"dnsenum discovered MX record {host} -> {target} (priority {priority})",
                        "evidence": f"{host} IN MX {priority} {target}",
                        "tool": "dnsenum",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            ns_m = _NS_RE.match(line)
            if ns_m:
                host = ns_m.group("host")
                target = ns_m.group("target")
                dedup_key = f"NS:{host}:{target}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"Name server: {target}",
                        "severity": "low",
                        "description": f"dnsenum discovered NS record {host} -> {target}",
                        "evidence": f"{host} IN NS {target}",
                        "tool": "dnsenum",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            cname_m = _CNAME_RE.match(line)
            if cname_m:
                host = cname_m.group("host")
                target = cname_m.group("target")
                dedup_key = f"CNAME:{host}:{target}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"CNAME: {host}",
                        "severity": "info",
                        "description": f"dnsenum discovered CNAME {host} -> {target}",
                        "evidence": f"{host} IN CNAME {target}",
                        "tool": "dnsenum",
                        "target": host,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            txt_m = _TXT_RE.match(line)
            if txt_m:
                host = txt_m.group("host")
                text = txt_m.group("text")
                dedup_key = f"TXT:{host}:{text}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"TXT record: {host}",
                        "severity": "info",
                        "description": f"dnsenum discovered TXT record {host} -> {text}",
                        "evidence": f"{host} IN TXT {text}",
                        "tool": "dnsenum",
                        "target": host,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            soa_detailed = _SOA_DETAIL_RE.match(line)
            if soa_detailed:
                mname = soa_detailed.group("mname")
                rname = soa_detailed.group("rname")
                serial = soa_detailed.group("serial")
                dedup_key = f"SOA:{mname}:{rname}:{serial}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                desc = f"DNS SOA: mname={mname}, rname={rname}"
                evidence = f"SOA {mname} {rname} serial={serial}"
                findings.append(
                    {
                        "title": f"DNS SOA: {mname}",
                        "severity": "info",
                        "description": desc,
                        "evidence": evidence,
                        "tool": "dnsenum",
                        "target": mname,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            soa_m = _SOA_RE.match(line)
            if soa_m:
                mname = soa_m.group("mname")
                rname = soa_m.group("rname")
                dedup_key = f"SOA:{mname}:{rname}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"DNS SOA: {mname}",
                        "severity": "info",
                        "description": f"DNS SOA record: mname={mname}, rname={rname}",
                        "evidence": f"SOA {mname} {rname}",
                        "tool": "dnsenum",
                        "target": mname,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            bk = _BRACKET_RE.match(line)
            if bk:
                host = bk.group("host")
                rtype = bk.group("type").upper()
                value = bk.group("value")
                dedup_key = f"{rtype}:{host}:{value}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = "info"
                findings.append(
                    {
                        "title": f"DNS {rtype}: {host}",
                        "severity": severity,
                        "description": f"dnsenum discovered {rtype} record {host} -> {value}",
                        "evidence": f"{host} IN {rtype} {value}",
                        "tool": "dnsenum",
                        "target": host,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            m_t = _THREAD_RE.match(line)
            if m_t:
                host = m_t.group("host")
                thread = m_t.group("thread")
                ip = m_t.group("ip")
                dedup_key = f"subdomain:{host}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                desc = f"dnsenum discovered subdomain {host} (thread {thread})"
                evidence = f"{host} [{ip}]" if ip else host
                if ip:
                    desc += f" [{ip}]"
                findings.append(
                    {
                        "title": f"Subdomain: {host}",
                        "severity": "info",
                        "description": desc,
                        "evidence": evidence,
                        "tool": "dnsenum",
                        "target": host,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            m = _HOST_RE.match(line)
            if not m:
                continue

            host = m.group("host")
            rtype = m.group("type").upper()
            value = m.group("value")

            dedup_key = f"{rtype}:{host}:{value}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "info"
            if rtype in {"NS", "MX"}:
                severity = "low"
            elif rtype in ("AXFR", "IXFR"):
                severity = "high"

            findings.append(
                {
                    "title": f"DNS {rtype}: {host}",
                    "severity": severity,
                    "description": f"dnsenum discovered {rtype} record {host} -> {value}",
                    "evidence": f"{host} IN {rtype} {value}",
                    "tool": "dnsenum",
                    "target": host,
                    "timestamp": _now_iso(),
                },
            )

        return findings
