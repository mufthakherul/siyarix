# SPDX-License-Identifier: AGPL-3.0-or-later

"""Grype JSON output parser — extracts vulnerability matches with package, severity, and fix."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "info",
    "Unknown": "info",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class GrypeParser:
    """Parse Grype JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        matches = data.get("matches", data.get("Matches", []))

        for match in matches:
            vuln = match.get("vulnerability", {})
            pkg = match.get("artifact", match.get("package", {}))
            fix_data = match.get("fix", {})

            vuln_id = vuln.get("id", vuln.get("ID", "unknown"))
            pkg_name = pkg.get("name", pkg.get("Name", "unknown"))
            pkg_version = pkg.get("version", pkg.get("Version", ""))

            dedup_key = f"{vuln_id}|{pkg_name}|{pkg_version}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity_raw = vuln.get("severity", vuln.get("Severity", "Unknown"))
            severity = _SEVERITY_MAP.get(str(severity_raw), "info")

            fix_state = fix_data.get("state", fix_data.get("State", "unknown"))
            fix_versions = fix_data.get("versions", fix_data.get("Versions", []))
            fix_str = ", ".join(fix_versions) if fix_versions else "not available"

            description = f"{vuln_id} in {pkg_name}@{pkg_version} — fix: {fix_str}"

            evidence = (
                f"Vulnerability: {vuln_id}, Package: {pkg_name}:{pkg_version}, "
                f"Severity: {severity_raw}, Fix: {fix_str}"
            )

            findings.append({
                "title": f"Grype: {vuln_id} ({pkg_name})",
                "severity": severity,
                "description": description,
                "evidence": evidence,
                "tool": "grype",
                "target": pkg_name,
                "timestamp": _now_iso(),
            })

        return findings
