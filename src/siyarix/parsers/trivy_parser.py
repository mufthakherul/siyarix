# SPDX-License-Identifier: AGPL-3.0-or-later

"""Trivy JSON output parser — extracts vulnerabilities per target with package, severity, and fix version."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "UNKNOWN": "info",
}


class TrivyParser:
    """Parse Trivy JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        results = data.get("Results", data.get("results", []))
        if not results and isinstance(data, list):
            results = data

        for result in results:
            target = result.get("Target", result.get("target", "unknown"))
            vulnerabilities = result.get("Vulnerabilities", result.get("vulnerabilities", []))

            for vuln in vulnerabilities:
                vuln_id = vuln.get("VulnerabilityID", vuln.get("vulnerability_id", "unknown"))
                pkg_name = vuln.get("PkgName", vuln.get("pkg_name", vuln.get("Package", "")))
                severity_raw = vuln.get("Severity", vuln.get("severity", "UNKNOWN")).upper()
                title = vuln.get("Title", vuln.get("title", ""))
                installed = vuln.get("InstalledVersion", vuln.get("installed_version", ""))
                fixed = vuln.get("FixedVersion", vuln.get("fixed_version", ""))

                dedup_key = f"{vuln_id}|{pkg_name}|{installed}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                severity = _SEVERITY_MAP.get(severity_raw, "info")

                description = f"{vuln_id} in {pkg_name}@{installed}"
                if fixed:
                    description += f" — fixed in {fixed}"
                if title:
                    description += f" | {title[:150]}"

                evidence = (
                    f"Package: {pkg_name}, Installed: {installed}, Fixed: {fixed or 'N/A'}, "
                    f"Severity: {severity_raw}, ID: {vuln_id}"
                )

                findings.append(
                    {
                        "title": f"Trivy: {vuln_id} ({pkg_name})",
                        "severity": severity,
                        "description": description,
                        "evidence": evidence,
                        "tool": "trivy",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
