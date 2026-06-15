# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bandit JSON output parser — extracts security issues with test_id, severity, confidence, and code."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "CRITICAL": "critical",
    "INFO": "info",
}

_SUMMARY_RE = re.compile(
    r"(?:issues|problems|total|scanned)[:\s]*(\d+)",
    re.IGNORECASE,
)


class BanditParser:
    """Parse Bandit JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", [])

        summary_m = _SUMMARY_RE.search(output)
        summary_count = summary_m.group(1) if summary_m else None

        for r in results:
            test_id = r.get("test_id", r.get("id", "unknown"))
            issue_severity = r.get("issue_severity", r.get("severity", "LOW")).upper()
            issue_confidence = r.get("issue_confidence", r.get("confidence", "LOW")).upper()
            filename = r.get("filename", r.get("file", ""))
            line_number = r.get("line_number", r.get("line", 0))
            code = r.get("code", r.get("code_line", ""))

            if isinstance(code, list):
                code = "\n".join(code)

            severity = _SEVERITY_MAP.get(issue_severity, "low")

            key = f"{test_id}:{filename}:{line_number}"
            if key in seen:
                continue
            seen.add(key)

            title = f"Bandit: {test_id}"
            description = f"Bandit {test_id} ({issue_severity}/{issue_confidence}) in {filename}:{line_number}"

            evidence = f"{filename}:{line_number} [{test_id}]"
            if code:
                evidence += f"\nCode: {code[:200]}"

            findings.append({
                "title": title,
                "severity": severity,
                "description": description,
                "evidence": evidence,
                "tool": "bandit",
                "target": filename,
                "timestamp": _now_iso(),
            })

        if summary_count:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"Bandit: {summary_count} issues",
                    "severity": "info",
                    "description": f"Bandit found {summary_count} issues",
                    "evidence": f"Total: {summary_count}",
                    "tool": "bandit",
                    "target": "",
                    "timestamp": _now_iso(),
                })

        return findings
