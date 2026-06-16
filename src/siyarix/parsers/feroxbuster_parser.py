# SPDX-License-Identifier: AGPL-3.0-or-later

"""Feroxbuster output parser — parses plain-text and JSON output for discovered URLs/paths."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_ROW_RE = re.compile(
    r"(?P<status>\d{3})\s+(?:\S+\s+)?(?P<size>\d+)(?:\s+(?P<lines>\d+)\s+(?P<words>\d+))?\s+(?P<url>\S+)"
)
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_SEVERITY_BY_STATUS = {
    200: "info",
    201: "info",
    204: "info",
    301: "low",
    302: "low",
    307: "low",
    308: "low",
    401: "medium",
    403: "medium",
    500: "high",
    502: "high",
    503: "high",
}
_WILDCARD_RE = re.compile(r"(?i)(wildcard|filter|excluded|discarded)\s+(\d+)")


class FeroxbusterParser:
    """Parse feroxbuster output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        lines = output.splitlines()

        if lines and _JSON_LINE_RE.match(lines[0].strip()):
            return self._parse_json(output)

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if _WILDCARD_RE.search(line_stripped):
                continue

            m = _ROW_RE.search(line_stripped)
            if not m:
                continue

            url = m.group("url")
            status = int(m.group("status"))
            size = int(m.group("size"))
            lines_count = int(m.group("lines")) if m.group("lines") else 0

            dedup_key = url
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = _SEVERITY_BY_STATUS.get(status, "info")

            findings.append(
                {
                    "title": f"Feroxbuster: {url} (HTTP {status})",
                    "severity": severity,
                    "description": f"Discovered {url} — HTTP {status}, size {size}, lines {lines_count}",
                    "evidence": f"{url} [Status: {status}, Size: {size}]",
                    "tool": "feroxbuster",
                    "target": url,
                    "timestamp": _now_iso(),
                }
            )

        return findings

    def _parse_json(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        lines = output.splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            url = obj.get("url", "")
            if not url:
                continue

            dedup_key = url
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            status = obj.get("status", 0)
            size = obj.get("content_length", obj.get("size", 0))
            severity = _SEVERITY_BY_STATUS.get(int(status), "info")

            findings.append(
                {
                    "title": f"Feroxbuster: {url} (HTTP {status})",
                    "severity": severity,
                    "description": f"Discovered {url} — HTTP {status}, size {size}",
                    "evidence": json.dumps(obj, default=str),
                    "tool": "feroxbuster",
                    "target": url,
                    "timestamp": _now_iso(),
                }
            )

        return findings
