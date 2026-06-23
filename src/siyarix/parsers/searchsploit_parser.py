# SPDX-License-Identifier: AGPL-3.0-or-later

"""searchsploit output parser — parses Exploit-DB search results (table, brief, JSON, -w URLs)."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_TABLE_LINE_RE = re.compile(
    r"\|\s*(?P<num>\d+)\s*\|\s*(?P<title>.+?)\s*\|\s*(?P<type>[\w\-]+)\s*\|\s*(?P<platform>\w+)\s*\|",
)

_BRIEF_LINE_RE = re.compile(
    r"\s*(?P<eid>\d+)\s+\|\s+(?P<title>.+?)\s+\|\s+(?P<type>[\w\-]+)\s+\|\s+(?P<platform>\w+)",
)


_URL_LINE_RE = re.compile(
    r"\s*(?P<eid>\d+)\s+\|\s+(?P<title>.+?)\s+\|\s+(?P<url>https?://\S+)",
)

_PATH_LINE_RE = re.compile(
    r"(?:Path|Location|File)[:\s]+(.+)",
    re.IGNORECASE,
)

_PATH_ENTRY_RE = re.compile(
    r"(?P<eid>\d+)\s*\|\s*(?P<path>\S+exploit\S+)",
    re.IGNORECASE,
)

_TITLE_PATH_RE = re.compile(
    r"\s*(?P<title>.+?)\s*\|\s*(?P<path>.+)",
)

_CVE_REF_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)

_SUMMARY_RE = re.compile(
    r"(?:Results|Found|Total)[:\s]*(\d+)",
    re.IGNORECASE,
)


class SearchsploitParser:
    """Parse searchsploit output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        query = "unknown"
        summary_count = ""

        lines = output.splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            m = _SUMMARY_RE.search(line)
            if m:
                summary_count = m.group(1)

            try:
                record = json.loads(line)
                eid = str(record.get("id", record.get("EDB-ID", "unknown")))
                title = record.get("title", record.get("description", "Unknown exploit"))
                etype = record.get("type", "unknown")
                platform = record.get("platform", "unknown")
                url = record.get("url", "")
                path = record.get("file", "")
                cve_ids = _CVE_REF_RE.findall(title + " " + str(record.get("cve", "")))
                key = f"edb:{eid}"
                if key not in seen:
                    seen.add(key)
                    evidence_parts = [f"EDB-ID: {eid}"]
                    if url:
                        evidence_parts.append(f"URL: {url}")
                    if path:
                        evidence_parts.append(f"Path: {path}")
                    if cve_ids:
                        evidence_parts.append(f"CVE: {', '.join(cve_ids)}")
                    findings.append(
                        {
                            "title": f"Exploit: {title[:80]}",
                            "severity": "high",
                            "description": f"Exploit-DB #{eid}: {title} ({etype}/{platform})",
                            "evidence": " | ".join(evidence_parts),
                            "tool": "searchsploit",
                            "target": query,
                            "timestamp": _now_iso(),
                        },
                    )
                continue
            except json.JSONDecodeError:
                pass

            if "searchsploit" in line.lower() and "exploit" in line.lower():
                parts = line.split()[-3:]
                query = " ".join(parts)
                continue

            m = _TABLE_LINE_RE.match(line)
            if m:
                eid = m.group("num")
                key = f"edb:{eid}"
                if key not in seen:
                    seen.add(key)
                    title = m.group("title")
                    cve_ids = _CVE_REF_RE.findall(title)
                    evidence_parts = [f"EDB-ID: {eid}"]
                    if cve_ids:
                        evidence_parts.append(f"CVE: {', '.join(cve_ids)}")
                    findings.append(
                        {
                            "title": f"Exploit #{eid}: {title[:60]}",
                            "severity": "high",
                            "description": f"searchsploit found exploit #{eid}: {title} ({m.group('type')}/{m.group('platform')})",
                            "evidence": " | ".join(evidence_parts),
                            "tool": "searchsploit",
                            "target": query,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _BRIEF_LINE_RE.match(line)
            if m:
                eid = m.group("eid")
                key = f"edb:{eid}"
                if key not in seen:
                    seen.add(key)
                    title = m.group("title")
                    cve_ids = _CVE_REF_RE.findall(title)
                    evidence_parts = [f"EDB-ID: {eid}"]
                    if cve_ids:
                        evidence_parts.append(f"CVE: {', '.join(cve_ids)}")
                    findings.append(
                        {
                            "title": f"Exploit #{eid}: {title[:60]}",
                            "severity": "high",
                            "description": f"searchsploit found exploit #{eid}: {title} ({m.group('type')}/{m.group('platform')})",
                            "evidence": " | ".join(evidence_parts),
                            "tool": "searchsploit",
                            "target": query,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _URL_LINE_RE.match(line)
            if m:
                eid = m.group("eid")
                key = f"edb-url:{eid}:{m.group('url')}"
                if key not in seen:
                    seen.add(key)
                    title = m.group("title")
                    cve_ids = _CVE_REF_RE.findall(title)
                    evidence_parts = [f"EDB-ID: {eid}", f"URL: {m.group('url')}"]
                    if cve_ids:
                        evidence_parts.append(f"CVE: {', '.join(cve_ids)}")
                    findings.append(
                        {
                            "title": f"Exploit #{eid}: {title[:60]}",
                            "severity": "high",
                            "description": f"searchsploit found exploit #{eid} at {m.group('url')}",
                            "evidence": " | ".join(evidence_parts),
                            "tool": "searchsploit",
                            "target": query,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _PATH_LINE_RE.search(line)
            if m:
                path = m.group(1).strip()
                key = f"path:{path}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Exploit-DB local path: {path[:60]}",
                            "severity": "info",
                            "description": f"searchsploit local path for {query}: {path}",
                            "evidence": path,
                            "tool": "searchsploit",
                            "target": query,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _PATH_ENTRY_RE.match(line)
            if m:
                eid = m.group("eid")
                path = m.group("path")
                key = f"path:{eid}:{path}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Exploit #{eid} local file",
                            "severity": "info",
                            "description": f"Exploit-DB file at {path}",
                            "evidence": f"Path: {path}",
                            "tool": "searchsploit",
                            "target": query,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _TITLE_PATH_RE.match(line)
            if m:
                title = m.group("title").strip()
                path = m.group("path").strip()
                key = f"path:{title}:{path}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Exploit: {title[:60]}",
                            "severity": "high",
                            "description": f"searchsploit found exploit: {title} at {path}",
                            "evidence": f"Title: {title} | Path: {path}",
                            "tool": "searchsploit",
                            "target": query,
                            "timestamp": _now_iso(),
                        },
                    )

        if summary_count:
            findings.append(
                {
                    "title": f"searchsploit results: {summary_count} exploits",
                    "severity": "info",
                    "description": f"searchsploit found {summary_count} exploits for {query}",
                    "evidence": f"Total: {summary_count}",
                    "tool": "searchsploit",
                    "target": query,
                    "timestamp": _now_iso(),
                },
            )

        return findings
