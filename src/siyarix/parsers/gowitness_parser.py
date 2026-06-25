# SPDX-License-Identifier: AGPL-3.0-or-later

"""Gowitness JSON report parser — extracts screenshots with URL, status code, title, and screenshot path."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso


class GowitnessParser:
    """Parse gowitness JSON report into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        try:
            data = json.loads(output)
            if isinstance(data, list):
                for entry in data:
                    r = self._extract(entry, seen)
                    if r:
                        findings.append(r)
            else:
                r = self._extract(data, seen)
                if r:
                    findings.append(r)
            return findings
        except json.JSONDecodeError:
            pass

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                data = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list):
                for entry in data:
                    r = self._extract(entry, seen)
                    if r:
                        findings.append(r)
            else:
                r = self._extract(data, seen)
                if r:
                    findings.append(r)

        return findings

    def _extract(self, entry: dict, seen: set[str]) -> dict | None:
        url = entry.get("url", entry.get("URL", ""))
        if not url or url in seen:
            return None
        seen.add(url)

        status_code = entry.get("status_code", entry.get("StatusCode", entry.get("status", 0)))
        title = entry.get("title", entry.get("Title", ""))
        screenshot_path = entry.get(
            "screenshot_path",
            entry.get("ScreenshotPath", entry.get("filename", "")),
        )
        final_url = entry.get("final_url", entry.get("FinalUrl", ""))
        response_time = entry.get("response_time", entry.get("responseTime", ""))

        description = f"Screenshot taken: {url}"
        if status_code:
            description += f" [HTTP {status_code}]"
        if title:
            description += f" — {title}"
        if final_url and final_url != url:
            description += f" (redirected to {final_url})"
        if response_time:
            description += f" ({response_time})"

        evidence = f"URL: {url}, Status: {status_code}, Title: {title}"
        if screenshot_path:
            evidence += f", Screenshot: {screenshot_path}"
        if response_time:
            evidence += f", ResponseTime: {response_time}"

        target = final_url or url

        return {
            "title": f"Gowitness: {url}",
            "severity": "info",
            "description": description,
            "evidence": evidence,
            "tool": "gowitness",
            "target": target,
            "timestamp": _now_iso(),
        }
