# SPDX-License-Identifier: AGPL-3.0-or-later

"""Gau (getallurls) output parser — extracts URLs from plain-text line-per-URL output."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_URL_RE = re.compile(r"(https?://\S+)", re.IGNORECASE)
_JS_RE = re.compile(r"\.js(\?|$)", re.IGNORECASE)
_PDF_RE = re.compile(r"\.pdf(\?|$)", re.IGNORECASE)
_ADMIN_RE = re.compile(r"(admin|login|dashboard|api|config|backup|\.env|wp-admin)", re.IGNORECASE)

_SUMMARY_RE = re.compile(
    r"(?:urls?|found|total|scanned)[:\s]*(\d+)",
    re.IGNORECASE,
)


class GauParser:
    """Parse gau/getallurls URL-per-line output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        summary_m = _SUMMARY_RE.search(output)
        summary_count = summary_m.group(1) if summary_m else None

        for raw in output.splitlines():
            line_stripped = raw.strip()
            if not line_stripped:
                continue

            m = _URL_RE.match(line_stripped)
            if not m:
                continue

            url = m.group(1)

            key = f"url:{url}"
            if key in seen:
                continue
            seen.add(key)

            if _JS_RE.search(url):
                findings.append(
                    {
                        "title": f"GAU: JavaScript file — {url}",
                        "severity": "info",
                        "description": f"JavaScript source file discovered: {url}",
                        "evidence": url,
                        "tool": "gau",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            if _PDF_RE.search(url):
                findings.append(
                    {
                        "title": f"GAU: PDF document — {url}",
                        "severity": "info",
                        "description": f"PDF document discovered: {url}",
                        "evidence": url,
                        "tool": "gau",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            if _ADMIN_RE.search(url):
                findings.append(
                    {
                        "title": f"GAU: Sensitive endpoint — {url}",
                        "severity": "low",
                        "description": f"Sensitive/admin endpoint discovered: {url}",
                        "evidence": url,
                        "tool": "gau",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            findings.append(
                {
                    "title": f"GAU: URL discovered — {url}",
                    "severity": "info",
                    "description": f"URL discovered via gau/getallurls: {url}",
                    "evidence": url,
                    "tool": "gau",
                    "target": url,
                    "timestamp": _now_iso(),
                },
            )

        if summary_count:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"GAU: {summary_count} URLs",
                        "severity": "info",
                        "description": f"gau discovered {summary_count} URLs",
                        "evidence": f"Total: {summary_count}",
                        "tool": "gau",
                        "target": "",
                        "timestamp": _now_iso(),
                    },
                )

        return findings
