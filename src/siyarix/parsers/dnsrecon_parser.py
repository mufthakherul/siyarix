# SPDX-License-Identifier: AGPL-3.0-or-later

"""dnsrecon output parser — parses DNS enumeration text, JSON, and CSV output."""

from __future__ import annotations

from . import _now_iso

import csv
import json
import re
import io

_BRACKET_RECORD_RE = re.compile(
    r"\[\*\]\s+(?P<type>[A-Z]+)\s+(?P<name>\S+)\s+(?P<value>\S.*)",
)

_RECORD_RE = re.compile(
    r"(?P<type>[A-Z]+)\s+(?P<name>\S+)\s+(?P<value>\S.*)",
)

_SOA_RE = re.compile(
    r"SOA\s+(?P<mname>\S+)\s+(?P<rname>\S+).*",
    re.IGNORECASE,
)

_ZONE_TRANSFER_RE = re.compile(
    r"Zone\s+transfer\s+(?:was\s+)?(?:successful|completed|permitted)",
    re.IGNORECASE,
)

_STATS_RE = re.compile(
    r"(?:found|discovered|total)\s+(\d+)\s+(?:record|host|domain)",
    re.IGNORECASE,
)

_SRV_RE = re.compile(
    r"SRV\s+(?P<name>\S+)\s+(?P<priority>\d+)\s+(?P<weight>\d+)\s+(?P<port>\d+)\s+(?P<target>\S+)",
    re.IGNORECASE,
)

_TXT_RE = re.compile(
    r"TXT\s+(?P<name>\S+)\s+(?P<text>.+)",
    re.IGNORECASE,
)

_SOA_DETAIL_RE = re.compile(
    r"SOA\s+(?P<mname>\S+)\s+(?P<rname>\S+)\s+(?P<serial>\d+)\s+(?P<refresh>\d+)\s+(?P<retry>\d+)\s+(?P<expire>\d+)\s+(?P<minimum>\d+)",
    re.IGNORECASE,
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_HEADER_RE = re.compile(
    r"^(?:\[.*?\]|-{3,}|={3,}|__+|\w+\s+\w+\s+.*)",
)


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    return stripped.splitlines()[0].strip().startswith(("[", "{"))


def _looks_like_csv(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    first = stripped.splitlines()[0].strip().lower()
    return "," in first and any(
        kw in first for kw in ("type", "name", "address", "target", "record")
    )


class DnsreconParser:
    """Parse dnsrecon output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        if _looks_like_json(output):
            try:
                return self._parse_json(output)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        if _looks_like_csv(output):
            try:
                return self._parse_csv(output)
            except (csv.Error, Exception):
                pass
        return self._parse_text(output)

    def _parse_json(self, json_str: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        data = json.loads(json_str)
        records = data if isinstance(data, list) else [data]

        for record in records:
            record_type = record.get("type", record.get("record_type", "UNKNOWN")).upper()
            name = record.get("name", record.get("domain", "unknown"))
            value = record.get("value", record.get("address", record.get("target", "")))

            dedup_key = f"{record_type}:{name}:{value}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "info"
            if record_type in ("AXFR", "IXFR"):
                severity = "high"
            elif record_type == "NS":
                severity = "low"
            elif record_type in ("MX", "SOA"):
                severity = "low"

            desc = f"dnsrecon discovered {record_type} record {name} -> {value}"
            evidence = f"{record_type} {name} {value}"

            soa_data = record.get("soa", {})
            if soa_data and isinstance(soa_data, dict):
                soa_str = "; ".join(f"{k}={v}" for k, v in soa_data.items())
                desc += f" [SOA: {soa_str}]"
                evidence += f" soa:{soa_str}"

            findings.append(
                {
                    "title": f"DNS {record_type} record: {name}",
                    "severity": severity,
                    "description": desc,
                    "evidence": evidence,
                    "tool": "dnsrecon",
                    "target": name,
                    "timestamp": _now_iso(),
                }
            )
        return findings

    def _parse_csv(self, csv_str: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        reader = csv.DictReader(io.StringIO(csv_str))

        for row in reader:
            record_type = row.get("type", row.get("record_type", "UNKNOWN")).upper()
            name = row.get("name", row.get("domain", "unknown"))
            value = row.get("value", row.get("address", row.get("target", "")))

            dedup_key = f"{record_type}:{name}:{value}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "info"
            if record_type in ("AXFR", "IXFR"):
                severity = "high"
            elif record_type == "NS":
                severity = "low"
            elif record_type in ("MX", "SOA"):
                severity = "low"

            findings.append(
                {
                    "title": f"DNS {record_type} record: {name}",
                    "severity": severity,
                    "description": f"dnsrecon discovered {record_type} record {name} -> {value}",
                    "evidence": f"{record_type} {name} {value}",
                    "tool": "dnsrecon",
                    "target": name,
                    "timestamp": _now_iso(),
                }
            )
        return findings

    def _parse_text(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        target_domain = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if "dnsrecon" in line.lower() and "domain" in line.lower():
                parts = line.split(":")
                if len(parts) > 1:
                    target_domain = parts[-1].strip()

            sm = _STATS_RE.search(line)
            if sm:
                count = sm.group(1)
                sk = f"stats:{target_domain}:{count}"
                if sk not in seen:
                    seen.add(sk)
                    findings.append(
                        {
                            "title": f"dnsrecon summary: {count} records",
                            "severity": "info",
                            "description": f"dnsrecon found {count} records for {target_domain}",
                            "evidence": line,
                            "tool": "dnsrecon",
                            "target": target_domain,
                            "timestamp": _now_iso(),
                        }
                    )

            if _ZONE_TRANSFER_RE.search(line):
                zk = f"zone_xfer:{target_domain}"
                if zk not in seen:
                    seen.add(zk)
                    findings.append(
                        {
                            "title": "DNS zone transfer permitted",
                            "severity": "high",
                            "description": f"DNS zone transfer is permitted for {target_domain} — potential information disclosure.",
                            "evidence": line,
                            "tool": "dnsrecon",
                            "target": target_domain,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            srv_m = _SRV_RE.match(line)
            if srv_m:
                name = srv_m.group("name")
                priority = srv_m.group("priority")
                weight = srv_m.group("weight")
                port = srv_m.group("port")
                target = srv_m.group("target")
                dedup_key = f"SRV:{name}:{target}:{port}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                desc = f"dnsrecon discovered SRV record {name} -> {target}:{port} (prio={priority}, weight={weight})"
                evidence = f"SRV {name} {priority} {weight} {port} {target}"
                findings.append(
                    {
                        "title": f"DNS SRV record: {name}",
                        "severity": "info",
                        "description": desc,
                        "evidence": evidence,
                        "tool": "dnsrecon",
                        "target": name,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            txt_m = _TXT_RE.match(line)
            if txt_m:
                name = txt_m.group("name")
                text = txt_m.group("text")
                dedup_key = f"TXT:{name}:{text}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"DNS TXT record: {name}",
                        "severity": "info",
                        "description": f"dnsrecon discovered TXT record {name} -> {text}",
                        "evidence": f"TXT {name} {text}",
                        "tool": "dnsrecon",
                        "target": name,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            soa_detailed = _SOA_DETAIL_RE.match(line)
            if soa_detailed:
                mname = soa_detailed.group("mname")
                rname = soa_detailed.group("rname")
                serial = soa_detailed.group("serial")
                refresh = soa_detailed.group("refresh")
                retry = soa_detailed.group("retry")
                expire = soa_detailed.group("expire")
                minimum = soa_detailed.group("minimum")
                dedup_key = f"SOA:{mname}:{rname}:{serial}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                desc = f"DNS SOA: mname={mname}, rname={rname}"
                evidence = f"SOA {mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} minimum={minimum}"
                findings.append(
                    {
                        "title": f"DNS SOA: {mname}",
                        "severity": "low",
                        "description": desc,
                        "evidence": evidence,
                        "tool": "dnsrecon",
                        "target": mname,
                        "timestamp": _now_iso(),
                    }
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
                        "severity": "low",
                        "description": f"DNS SOA record: mname={mname}, rname={rname}",
                        "evidence": f"SOA {mname} {rname}",
                        "tool": "dnsrecon",
                        "target": mname,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            m = _BRACKET_RECORD_RE.match(line)
            if not m:
                m = _RECORD_RE.match(line)
            if not m:
                continue

            record_type = m.group("type").upper()
            name = m.group("name")
            value = m.group("value")

            dedup_key = f"{record_type}:{name}:{value}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "info"
            if record_type in ("AXFR", "IXFR"):
                severity = "high"
            elif record_type == "NS":
                severity = "low"
            elif record_type in ("MX", "SOA"):
                severity = "low"

            findings.append(
                {
                    "title": f"DNS {record_type} record: {name}",
                    "severity": severity,
                    "description": f"dnsrecon discovered {record_type} record {name} -> {value}",
                    "evidence": f"{record_type} {name} {value}",
                    "tool": "dnsrecon",
                    "target": name,
                    "timestamp": _now_iso(),
                }
            )

        return findings
