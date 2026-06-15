# SPDX-License-Identifier: AGPL-3.0-or-later

"""smbmap output parser — parses SMB share/file enumeration, recursive listing, and host list output."""

from __future__ import annotations

import json
import re

from . import _now_iso

_SHARE_RE = re.compile(
    r"\s*(?P<share>\S+)\s+\(?(?P<perm>READ(?:\s*,\s*WRITE)?|WRITE|ACCESS DENIED|READ ONLY)\)?",
    re.IGNORECASE,
)

_FILE_RE = re.compile(
    r"\s*(?P<name>\S+)\s+(?P<size>\d+)\s+(?P<perms>..-)\s+.*",
)

_DISK_RE = re.compile(
    r"\s*Disk\s*[:\]]\s*(?P<share>\S+)",
    re.IGNORECASE,
)

_RECURSIVE_FILE_RE = re.compile(
    r"\s*[`|]\s*(?P<path>\.\\(?:[^\\]+\\?)+)\s*$",
)

_RECURSIVE_DIR_RE = re.compile(
    r"\s*[`|]\s*(?P<path>\.\\(?:[^\\]+\\?)+[/\\])$",
)

_HOST_RE = re.compile(
    r"\(?(?P<host>\d{1,3}(?:\.\d{1,3}){3})\)?\s*[:\-]\s*(?P<desc>.+)?",
)

_SHARES_LINE_RE = re.compile(
    r"Shares:\s*(.+)",
    re.IGNORECASE,
)

_SHARE_ENTRY_RE = re.compile(
    r"(?P<share>\S+)\s+\((?P<perm>[^)]+)\)",
)

_DISK_USAGE_RE = re.compile(
    r"([\d.]+[KMGT]?B)\s+used\s+out\s+of\s+([\d.]+[KMGT]?B)",
    re.IGNORECASE,
)

_TARGET_HEADER_RE = re.compile(
    r"\[?Target\]?\s*:\s*(?P<target>\S+)",
    re.IGNORECASE,
)

_JSON_RE = re.compile(r"^\s*[{\[]")


class SmbmapParser:
    """Parse smbmap output into normalized finding dictionaries."""

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
                    perm = item.get("permission", item.get("access", ""))
                    target = item.get("target", item.get("host", "unknown"))
                    if share and perm:
                        dedup_key = f"share|{target}|{share}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        severity = "critical" if "WRITE" in str(perm).upper() else "info"
                        findings.append({
                            "title": f"SMB share: {share} ({perm})",
                            "severity": severity,
                            "description": f"smbmap discovered share {share} on {target} with {perm} access",
                            "evidence": json.dumps(item),
                            "tool": "smbmap",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                    fname = item.get("filename", item.get("name", ""))
                    fsize = item.get("size", item.get("file_size", 0))
                    if fname and "permission" not in item:
                        dedup_key = f"file|{target}|{share}|{fname}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings.append({
                            "title": f"SMB file: {fname}",
                            "severity": "info",
                            "description": f"File {fname} ({fsize} bytes) on {target}",
                            "evidence": json.dumps(item),
                            "tool": "smbmap",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                    du = item.get("disk_usage", item.get("used", ""))
                    if du:
                        findings.append({
                            "title": "SMB disk usage",
                            "severity": "info",
                            "description": f"Disk usage: {du}",
                            "evidence": json.dumps(item),
                            "tool": "smbmap",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                return findings
            except json.JSONDecodeError:
                pass

        target = "unknown"
        current_share = ""
        in_recursive = False

        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                in_recursive = False
                continue

            thm = _TARGET_HEADER_RE.match(line)
            if thm:
                target = thm.group("target").strip()
                continue

            hm = _HOST_RE.match(line)
            if hm:
                target = hm.group("host")
                desc = hm.group("desc") or ""
                findings.append({
                    "title": f"SMB target: {target}",
                    "severity": "info",
                    "description": f"smbmap scanning target {target}: {desc}",
                    "evidence": line,
                    "tool": "smbmap",
                    "target": target,
                    "timestamp": _now_iso(),
                })
                continue

            if "target" in line.lower() and ":" in line and len(line.split()) < 6:
                parts = line.split(":", 1)
                target = parts[-1].strip()
                continue

            m = _DISK_RE.match(line)
            if m:
                current_share = m.group("share")
                continue

            slm = _SHARES_LINE_RE.search(line)
            if slm:
                shares_text = slm.group(1)
                for match in _SHARE_ENTRY_RE.finditer(shares_text):
                    share = match.group("share")
                    perm = match.group("perm").upper()
                    severity = "critical" if "WRITE" in perm else "info"
                    dedup_key = f"share|{target}|{share}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    findings.append({
                        "title": f"SMB share: {share} ({perm})",
                        "severity": severity,
                        "description": f"smbmap discovered share {share} on {target} with {perm} access",
                        "evidence": f"share: {share} permission: {perm} target: {target}",
                        "tool": "smbmap",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _SHARE_RE.match(line)
            if m:
                current_share = m.group("share")
                perm = m.group("perm").upper()
                severity = "critical" if "WRITE" in perm else "info"
                dedup_key = f"share|{target}|{current_share}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append({
                    "title": f"SMB share: {current_share} ({perm})",
                    "severity": severity,
                    "description": f"smbmap discovered share {current_share} on {target} with {perm} access",
                    "evidence": f"share: {current_share} permission: {perm} target: {target}",
                    "tool": "smbmap",
                    "target": target,
                    "timestamp": _now_iso(),
                })
                continue

            du = _DISK_USAGE_RE.search(line)
            if du:
                findings.append({
                    "title": "SMB disk usage",
                    "severity": "info",
                    "description": f"Disk usage: {du.group(1)} used / {du.group(2)} total on {target}\\{current_share}",
                    "evidence": line,
                    "tool": "smbmap",
                    "target": target,
                    "timestamp": _now_iso(),
                })
                continue

            rm = _RECURSIVE_DIR_RE.match(line)
            if rm:
                in_recursive = True
                dedup_key = f"dir|{target}|{current_share}|{rm.group('path')}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append({
                    "title": f"SMB directory: {rm.group('path')}",
                    "severity": "info",
                    "description": f"Directory {rm.group('path')} in {current_share} on {target}",
                    "evidence": line,
                    "tool": "smbmap",
                    "target": target,
                    "timestamp": _now_iso(),
                })
                continue

            rm = _RECURSIVE_FILE_RE.match(line)
            if rm:
                in_recursive = True
                dedup_key = f"file|{target}|{current_share}|{rm.group('path')}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append({
                    "title": f"SMB file: {rm.group('path')}",
                    "severity": "info",
                    "description": f"File {rm.group('path')} in {current_share} on {target}",
                    "evidence": line,
                    "tool": "smbmap",
                    "target": target,
                    "timestamp": _now_iso(),
                })
                continue

            if "[" in line and "]" in line and ":" in line and len(line.split()) < 5:
                continue

            m = _FILE_RE.match(line)
            if m:
                dedup_key = f"file|{target}|{current_share}|{m.group('name')}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append({
                    "title": f"SMB file: {m.group('name')}",
                    "severity": "info",
                    "description": f"File {m.group('name')} ({m.group('size')} bytes) in {current_share} on {target}",
                    "evidence": line,
                    "tool": "smbmap",
                    "target": target,
                    "timestamp": _now_iso(),
                })

        return findings
