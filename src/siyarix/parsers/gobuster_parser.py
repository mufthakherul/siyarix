# SPDX-License-Identifier: AGPL-3.0-or-later

"""Gobuster output parser — parses gobuster dir/dns plain-text output."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

# HTTP status code → severity
_STATUS_SEVERITY: dict[int, str] = {
    200: "info",
    204: "info",
    301: "info",
    302: "info",
    307: "info",
    308: "info",
    401: "low",
    403: "low",
    405: "info",
    500: "medium",
    501: "medium",
    503: "medium",
}

# e.g. "/admin (Status: 200) [Size: 1234]"
_LINE_RE = re.compile(r"^(/\S*)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?")


def _severity_for_status(status: int) -> str:
    return _STATUS_SEVERITY.get(status, "info")


class GobusterParser:
    """Parses gobuster text output lines into finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        """Parse gobuster *output* and return a list of finding dicts."""
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        target = "unknown"

        for line in output.splitlines():
            line = line.strip()

            # Extract base URL from gobuster header
            if line.startswith(("Url:", "Url ")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    target = parts[1].strip()
                continue

            m = _LINE_RE.match(line)
            if not m:
                continue

            path = m.group(1)
            status = int(m.group(2))
            size = m.group(3) or "unknown"
            severity = _severity_for_status(status)

            findings.append(
                {
                    "title": f"Directory found: {path} (HTTP {status})",
                    "severity": severity,
                    "description": (
                        f"Gobuster discovered path {path!r} returning HTTP {status} "
                        f"(size: {size} bytes)"
                    ),
                    "evidence": f"{target}{path} → HTTP {status}",
                    "tool": "gobuster",
                    "target": target,
                    "timestamp": _now_iso(),
                },
            )

        return findings
