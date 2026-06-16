# SPDX-License-Identifier: AGPL-3.0-or-later

"""smbclient output parser — parses SMB client listing/transfer output and -L server listing."""

from __future__ import annotations

import json
import re

from . import _now_iso

_SHARE_RE = re.compile(
    r"\s*(?P<share>\S+)\s+(?P<type>\S+)\b",
    re.IGNORECASE,
)

_FILE_RE = re.compile(
    r"\s*(?P<type>[AD])\s+(?P<rest>.+?)\s+"
    r"(?P<date>\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+"
    r"(?P<name>.+)",
)

_CONNECTED_RE = re.compile(
    r"(?:connected|session|server)\s+(?:to|setup|started)",
    re.IGNORECASE,
)

_SERVER_LINE_RE = re.compile(
    r"^\s*(?P<server>\S+)\s{2,}(?P<comment>.+)$",
)

_DOMAIN_RE = re.compile(
    r"Domain\s*=\s*\[?([^\]]+)\]?",
    re.IGNORECASE,
)

_OS_RE = re.compile(
    r"OS\s*=\s*\[?([^\]]+)\]?",
    re.IGNORECASE,
)

_SERVER_DESC_RE = re.compile(
    r"(?:Server|server)\s*=\s*\[?([^\]]+)\]?",
    re.IGNORECASE,
)

_SMB_VER_RE = re.compile(
    r"SMB\s*(?:version|v)?\s*[=:]\s*([\d.]+)",
    re.IGNORECASE,
)

_NETBIOS_RE = re.compile(
    r"(?:NetBIOS|nbt|nbname)\s*[=:]\s*(\S+)",
    re.IGNORECASE,
)

_JSON_RE = re.compile(r"^\s*[{\[]")


class SmbclientParser:
    """Parse smbclient output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        stripped = output.strip()
        if not stripped:
            return findings

        seen: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    share = item.get("share", item.get("name", ""))
                    server = item.get("server", item.get("host", "unknown"))
                    fsize = item.get("size", item.get("file_size", 0))
                    if share:
                        dedup_key = f"share|{server}|{share}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings.append(
                            {
                                "title": f"SMB share discovered: {share}",
                                "severity": "medium",
                                "description": f"smbclient discovered share {share} on {server}",
                                "evidence": json.dumps(item),
                                "tool": "smbclient",
                                "target": server,
                                "timestamp": _now_iso(),
                            }
                        )
                    fname = item.get("filename", item.get("name", ""))
                    if fname:
                        dedup_key = f"file|{server}|{fname}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings.append(
                            {
                                "title": f"SMB file: {fname}",
                                "severity": "info",
                                "description": f"File {fname} ({fsize} bytes) accessible on {server}",
                                "evidence": json.dumps(item),
                                "tool": "smbclient",
                                "target": server,
                                "timestamp": _now_iso(),
                            }
                        )
                return findings
            except json.JSONDecodeError:
                pass

        server = "unknown"
        current_share = ""
        domain_name = ""
        os_name = ""

        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue

            lower = line.lower()

            dom = _DOMAIN_RE.search(line)
            if dom:
                domain_name = dom.group(1).strip()
                findings.append(
                    {
                        "title": f"SMB server domain: {domain_name}",
                        "severity": "info",
                        "description": f"Domain/workgroup: {domain_name}",
                        "evidence": line,
                        "tool": "smbclient",
                        "target": server,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            osm = _OS_RE.search(line)
            if osm:
                os_name = osm.group(1).strip()
                findings.append(
                    {
                        "title": f"SMB server OS: {os_name}",
                        "severity": "info",
                        "description": f"Server OS: {os_name}",
                        "evidence": line,
                        "tool": "smbclient",
                        "target": server,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            sdm = _SERVER_DESC_RE.search(line)
            if sdm:
                sv = sdm.group(1).strip()
                findings.append(
                    {
                        "title": f"SMB server: {sv}",
                        "severity": "info",
                        "description": f"SMB server description: {sv}",
                        "evidence": line,
                        "tool": "smbclient",
                        "target": sv,
                        "timestamp": _now_iso(),
                    }
                )
                if server == "unknown":
                    server = sv
                continue

            svm = _SMB_VER_RE.search(line)
            if svm:
                findings.append(
                    {
                        "title": f"SMB protocol version: {svm.group(1)}",
                        "severity": "info",
                        "description": f"SMB version {svm.group(1)} detected on {server}",
                        "evidence": line,
                        "tool": "smbclient",
                        "target": server,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            nbm = _NETBIOS_RE.search(line)
            if nbm:
                nbname = nbm.group(1).strip()
                findings.append(
                    {
                        "title": f"NetBIOS name: {nbname}",
                        "severity": "info",
                        "description": f"NetBIOS name {nbname} for {server}",
                        "evidence": line,
                        "tool": "smbclient",
                        "target": server,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if "server" in lower and ("\\\\" in line or "//" in line or ":" in line):
                parts = re.split(r"[\s:]+", line, maxsplit=1)
                if len(parts) > 1:
                    server = parts[-1].strip()
                continue

            if "session" in lower and "request" in lower:
                continue

            if _CONNECTED_RE.search(lower):
                findings.append(
                    {
                        "title": f"SMB session: {server}",
                        "severity": "info",
                        "description": f"smbclient successfully connected to SMB server {server}",
                        "evidence": line,
                        "tool": "smbclient",
                        "target": server,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if "\\" in line and line.strip() == current_share.strip():
                continue

            m = _SHARE_RE.match(line)
            if m:
                current_share = m.group("share")
                share_type = m.group("type").lower()
                dedup_key = f"share|{server}|{current_share}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"SMB share discovered: {current_share}",
                        "severity": "medium",
                        "description": f"smbclient discovered share {current_share} ({share_type}) on {server}",
                        "evidence": f"server: {server} share: {current_share} type: {share_type}",
                        "tool": "smbclient",
                        "target": server,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            m = _FILE_RE.match(line)
            if m:
                fname = m.group("name")
                fdate = m.group("date")
                rest = m.group("rest")
                size_m = re.search(r"(\d+)\s*$", rest)
                fsize = size_m.group(1) if size_m else "0"
                dedup_key = f"file|{server}|{current_share}|{fname}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"SMB file: {fname}",
                        "severity": "info",
                        "description": f"File {fname} ({fsize} bytes, {fdate}) in {current_share} on {server}",
                        "evidence": line,
                        "tool": "smbclient",
                        "target": server,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
