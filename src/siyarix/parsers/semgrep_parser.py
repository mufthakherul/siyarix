# SPDX-License-Identifier: AGPL-3.0-or-later

"""Semgrep JSON output parser — extracts check_id, path, line, severity, and message from scan results."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}
_SUMMARY_RE = re.compile(
    r"(?:findings|results|total|scanned)[:\s]*(\d+)",
    re.IGNORECASE,
)


class SemgrepParser:
    """Parse Semgrep JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        lines = output.splitlines()

        if not lines or not _JSON_LINE_RE.match(lines[0].strip()):
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        results = data if isinstance(data, list) else data.get("results", [])

        summary_count = ""
        summary_m = _SUMMARY_RE.search(output)
        if summary_m:
            summary_count = summary_m.group(1)

        for r in results:
            check_id = r.get("check_id", "unknown")
            path = r.get("path", "")
            start = r.get("start", {}) or {}
            line_num = start.get("line", 0)
            severity_raw = r.get("extra", {}).get("severity", "info")
            message = r.get("extra", {}).get("message", "")
            severity = _SEVERITY_MAP.get(severity_raw.upper(), "info")

            key = f"{check_id}:{path}:{line_num}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"Semgrep: {check_id}",
                        "severity": severity,
                        "description": message or f"Semgrep finding: {check_id}",
                        "evidence": f"{path}:{line_num} [{check_id}]",
                        "tool": "semgrep",
                        "target": path,
                        "timestamp": _now_iso(),
                    }
                )

        if summary_count:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"Semgrep: {summary_count} findings",
                        "severity": "info",
                        "description": f"Semgrep found {summary_count} findings",
                        "evidence": f"Total: {summary_count}",
                        "tool": "semgrep",
                        "target": "",
                        "timestamp": _now_iso(),
                    }
                )

        return findings
