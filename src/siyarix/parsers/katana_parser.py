# SPDX-License-Identifier: AGPL-3.0-or-later

"""Katana JSON output parser — extracts discovered URLs with source, status code, and content type."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")


class KatanaParser:
    """Parse katana JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped or not _JSON_LINE_RE.match(line_stripped):
                continue

            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            url = obj.get("url", obj.get("URL", obj.get("request", "")))
            if not url:
                continue

            url_path = url.split("?")[0]
            dedup_key = url_path
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            source = obj.get("source", obj.get("Source", ""))
            status_code = obj.get("status_code", obj.get("StatusCode", 0))
            content_type = obj.get("content_type", obj.get("ContentType", ""))

            description = f"Discovered URL: {url}"
            if source:
                description += f" (source: {source})"
            if status_code:
                description += f" [HTTP {status_code}]"

            severity = "info"
            if status_code and int(status_code) in (401, 403):
                severity = "medium"
            elif status_code and int(status_code) >= 500:
                severity = "high"

            findings.append({
                "title": f"Katana: {url}",
                "severity": severity,
                "description": description,
                "evidence": f"URL: {url}, Source: {source}, Status: {status_code}, Type: {content_type}",
                "tool": "katana",
                "target": url_path,
                "timestamp": _now_iso(),
            })

        return findings
