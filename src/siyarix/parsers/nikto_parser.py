# SPDX-License-Identifier: AGPL-3.0-or-later

"""Nikto output parser — parses nikto plain-text output."""

from __future__ import annotations

from . import _now_iso

import re

# OSVDB ranges mapped to severity
_OSVDB_SEVERITY: list[tuple[range, str]] = [
    (range(1, 1000), "low"),
    (range(1000, 5000), "medium"),
    (range(5000, 10000), "high"),
    (range(10000, 999999), "medium"),
]

_TARGET_RE = re.compile(r"\+ Target IP:\s+(\S+)")
_HOST_RE = re.compile(r"\+ Target Hostname:\s+(\S+)")
_PORT_RE = re.compile(r"\+ Target Port:\s+(\d+)")
_OSVDB_RE = re.compile(r"OSVDB-(\d+)")


def _severity_for_osvdb(osvdb_id: int) -> str:
    for rng, sev in _OSVDB_SEVERITY:
        if osvdb_id in rng:
            return sev
    return "info"

class NiktoParser:
    """Parses nikto text output (lines starting with ``+``) into finding dicts."""

    def parse(self, output: str) -> list[dict]:
        """Parse nikto text *output* and return a list of finding dicts."""
        findings: list[dict] = []
        target_ip = "unknown"
        target_host = "unknown"
        target_port = "80"

        for line in output.splitlines():
            # Extract metadata
            m = _TARGET_RE.match(line)
            if m:
                target_ip = m.group(1)
                continue
            m = _HOST_RE.match(line)
            if m:
                target_host = m.group(1)
                continue
            m = _PORT_RE.match(line)
            if m:
                target_port = m.group(1)
                continue

            # Finding lines start with "+"
            if not line.startswith("+"):
                continue

            content = line[1:].strip()
            # Skip header/summary lines
            if (
                content.startswith("Target")
                or content.startswith("Start Time")
                or content.startswith("End Time")
                or content.startswith("1 host")
            ):
                continue

            osvdb_match = _OSVDB_RE.search(content)
            severity = "info"
            if osvdb_match:
                severity = _severity_for_osvdb(int(osvdb_match.group(1)))

            target = target_host if target_host != "unknown" else target_ip
            findings.append(
                {
                    "title": content[:120],
                    "severity": severity,
                    "description": content,
                    "evidence": f"{target}:{target_port}",
                    "tool": "nikto",
                    "target": target,
                    "timestamp": _now_iso(),
                }
            )

        return findings
