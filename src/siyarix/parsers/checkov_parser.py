# SPDX-License-Identifier: AGPL-3.0-or-later

"""Checkov JSON output parser — extracts failed checks with resource, guideline, and severity."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "FAILED": "high",
    "PASSED": "info",
}


class CheckovParser:
    """Parse Checkov JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", {})

        for result_type in ("failed_checks", "passed_checks"):
            checks = results.get(result_type, [])
            for check in checks:
                check_id = check.get("check_id", "unknown")
                resource = check.get("resource", "")
                guideline = check.get("guideline", check.get("guidelines", ""))
                severity_raw = check.get("severity", check.get("check_result", {}).get("result", "INFO"))
                file_path = check.get("file_path", check.get("filePath", ""))
                repo_name = check.get("repo_name", check.get("repo", ""))

                dedup_key = f"{check_id}|{resource or file_path}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                severity_str = str(severity_raw).upper()
                severity = _SEVERITY_MAP.get(severity_str, "info")

                if result_type == "passed_checks":
                    severity = "info"

                description = f"Checkov {result_type.replace('_', ' ')}: {check_id}"
                if resource:
                    description += f" on {resource}"

                target = resource or file_path or repo_name

                findings.append({
                    "title": f"Checkov: {check_id}",
                    "severity": severity,
                    "description": description,
                    "evidence": f"Resource: {resource}, File: {file_path}",
                    "tool": "checkov",
                    "target": target,
                    "timestamp": _now_iso(),
                })

        return findings
