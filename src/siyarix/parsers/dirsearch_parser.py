# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dirsearch output parser — parses dirsearch plain-text output for discovered URLs and redirects."""

from __future__ import annotations

from . import _now_iso

import re

_ROW_RE = re.compile(
    r"(?P<status>\d{3})\s+(?P<size>\S+)\s+(?P<url>https?://\S+)(?:\s+->\s+(?P<redirect>\S+))?"
)
_SEVERITY_BY_STATUS = {
    200: "info",
    201: "info",
    204: "info",
    301: "low",
    302: "low",
    303: "low",
    307: "low",
    308: "low",
    400: "info",
    401: "medium",
    403: "medium",
    500: "high",
    502: "high",
    503: "high",
}


class DirsearchParser:
    """Parse dirsearch output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        target = "unknown"

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if line_stripped.startswith("Target:"):
                parts = line_stripped.split(":", 1)
                if len(parts) == 2:
                    target = parts[1].strip()
                continue

            m = _ROW_RE.search(line_stripped)
            if not m:
                continue

            url = m.group("url")
            status = int(m.group("status"))
            size = m.group("size")
            redirect = m.group("redirect")

            dedup_key = url
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = _SEVERITY_BY_STATUS.get(status, "info")

            description = f"Dirsearch discovered {url} — HTTP {status}, size {size}"
            if redirect:
                description += f", redirects to {redirect}"

            findings.append(
                {
                    "title": f"Dirsearch: {url} (HTTP {status})",
                    "severity": severity,
                    "description": description,
                    "evidence": f"{url} [Status: {status}, Size: {size}"
                    + (f", Redirect: {redirect}" if redirect else "")
                    + "]",
                    "tool": "dirsearch",
                    "target": target,
                    "timestamp": _now_iso(),
                }
            )

        return findings
