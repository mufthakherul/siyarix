# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hakrawler web crawler output parser — parses URL-per-line output."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_URL_RE = re.compile(r"^(?P<url>https?://\S+)", re.IGNORECASE)

_EXT_SEVERITY = {
    ".js": "medium",
    ".json": "info",
    ".php": "medium",
    ".asp": "medium",
    ".aspx": "medium",
    ".jsp": "medium",
    ".action": "medium",
    ".do": "medium",
    ".bak": "high",
    ".old": "high",
    ".backup": "high",
    ".sql": "high",
    ".dump": "high",
    ".db": "medium",
    ".env": "critical",
    ".git": "critical",
    ".svn": "critical",
    ".config": "high",
    ".yml": "medium",
    ".yaml": "medium",
    ".xml": "info",
    ".pdf": "low",
    ".doc": "low",
    ".xls": "low",
    ".zip": "medium",
    ".tar": "medium",
    ".gz": "medium",
    ".pem": "critical",
    ".key": "critical",
    ".cert": "high",
    ".p12": "critical",
}

_METHOD_RE = re.compile(r"^\[(?P<method>[A-Z]+)\]\s*(?P<url>https?://\S+)", re.IGNORECASE)


class HakrawlerParser:
    """Parse hakrawler URL-per-line output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _METHOD_RE.match(line)
            if m:
                url = m.group("url")
                method = m.group("method")
            else:
                url = None
                method = ""

            if not url:
                m = _URL_RE.match(line)
                if m:
                    url = m.group("url")
                else:
                    continue

            if url in seen:
                continue
            seen.add(url)

            severity = "info"
            for ext, sev in _EXT_SEVERITY.items():
                if url.lower().endswith(ext):
                    severity = sev
                    break
            if any(
                x in url.lower()
                for x in ("admin", "login", "api", "wp-admin", "console", "dashboard")
            ):
                severity = "medium" if severity == "info" else severity

            desc = f"hakrawler discovered endpoint: {url}"
            evidence = url
            if method:
                desc += f" [{method}]"
                evidence += f"; method:{method}"

            findings.append(
                {
                    "title": f"Endpoint: {url[:80]}",
                    "severity": severity,
                    "description": desc,
                    "evidence": evidence,
                    "tool": "hakrawler",
                    "target": url,
                    "timestamp": _now_iso(),
                },
            )
        return findings
