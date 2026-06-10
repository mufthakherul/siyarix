# SPDX-License-Identifier: AGPL-3.0-or-later

"""ffuf output parser — parses ffuf text output lines."""

from __future__ import annotations

from . import _now_iso

import re

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

_ROW_RE = re.compile(
    r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+),\s*Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)\]"
)
_URL_RE = re.compile(r"^::\s*URL:\s*(?P<url>\S+)")


class FfufParser:
    """Parse ffuf output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        base_url = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            url_match = _URL_RE.match(line)
            if url_match:
                base_url = url_match.group("url")
                continue

            m = _ROW_RE.match(line)
            if not m:
                continue

            path = m.group("path")
            status = int(m.group("status"))
            size = m.group("size")
            severity = _SEVERITY_BY_STATUS.get(status, "info")
            full_target = (
                f"{base_url.rstrip('/')}/{path.lstrip('/')}" if base_url != "unknown" else path
            )
            findings.append(
                {
                    "title": f"ffuf discovered endpoint {path} (HTTP {status})",
                    "severity": severity,
                    "description": f"ffuf matched path {path} with HTTP {status} and response size {size}.",
                    "evidence": full_target,
                    "tool": "ffuf",
                    "target": base_url,
                    "timestamp": _now_iso(),
                }
            )

        return findings
