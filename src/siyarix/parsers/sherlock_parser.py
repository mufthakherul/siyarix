# SPDX-License-Identifier: AGPL-3.0-or-later

"""Sherlock social media username search output parser."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*\{")

_SUMMARY_RE = re.compile(
    r"(?:found|total|results|sites)[:\s]*(\d+)",
    re.IGNORECASE,
)


class SherlockParser:
    """Parse Sherlock JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        summary_count = ""

        if _JSON_RE.match(output):
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    summary_m = _SUMMARY_RE.search(output)
                    if summary_m:
                        summary_count = summary_m.group(1)
                    for site_name, result in data.items():
                        if isinstance(result, dict):
                            status = result.get("status", "").lower()
                            url = result.get("url", result.get("url_user", ""))
                            if status in ("claimed", "yes", "true"):
                                severity = (
                                    "medium"
                                    if any(
                                        x in site_name.lower()
                                        for x in (
                                            "linkedin",
                                            "twitter",
                                            "facebook",
                                            "instagram",
                                            "github",
                                        )
                                    )
                                    else "info"
                                )
                                key = f"site:{site_name.lower()}"
                                if key not in seen:
                                    seen.add(key)
                                    findings.append(
                                        {
                                            "title": f"Social: {site_name}",
                                            "severity": severity,
                                            "description": f"Sherlock found username on {site_name}"
                                            + (f" at {url}" if url else ""),
                                            "evidence": url or site_name,
                                            "tool": "sherlock",
                                            "target": site_name,
                                            "timestamp": _now_iso(),
                                        },
                                    )
            except json.JSONDecodeError:
                pass

        for raw in output.splitlines():
            line = raw.strip()
            if not line or _JSON_RE.match(line):
                continue
            if "[+]" in line or "Found" in line:
                key = f"line:{line[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Sherlock: {line[:60]}",
                            "severity": "info",
                            "description": f"Sherlock result: {line}",
                            "evidence": raw.strip(),
                            "tool": "sherlock",
                            "target": "unknown",
                            "timestamp": _now_iso(),
                        },
                    )

        if summary_count:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"Sherlock: {summary_count} sites",
                        "severity": "info",
                        "description": f"Sherlock found username on {summary_count} sites",
                        "evidence": f"Total: {summary_count}",
                        "tool": "sherlock",
                        "target": "unknown",
                        "timestamp": _now_iso(),
                    },
                )

        return findings
