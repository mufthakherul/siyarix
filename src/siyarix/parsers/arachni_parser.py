# SPDX-License-Identifier: AGPL-3.0-or-later

"""Arachni web scanner output parser — parses Arachni JSON reports."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


class ArachniParser:
    """Parse Arachni JSON report output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        if _JSON_RE.match(output):
            try:
                data = json.loads(output)
                issues = data.get("issues", [])
                for issue in issues:
                    name = issue.get("name", issue.get("check", {}).get("name", "Unknown issue"))
                    severity_raw = issue.get("severity", "info").lower()
                    severity = _SEVERITY_MAP.get(severity_raw, "info")
                    description = issue.get(
                        "description", issue.get("check", {}).get("description", ""),
                    )
                    url = issue.get("vector", {}).get("action", "unknown")
                    parameter = issue.get("vector", {}).get("input", "")
                    cwe = issue.get("cwe", [])
                    if isinstance(cwe, list):
                        cwe = [str(x) for x in cwe]
                    elif isinstance(cwe, (int, str)):
                        cwe = [str(cwe)]
                    cwe_str = ", ".join(f"CWE-{c}" for c in cwe) if cwe else ""
                    tag = issue.get("check", {}).get("shortname", "")
                    refs = issue.get("references", [])
                    if isinstance(refs, dict):
                        refs = list(refs.values())
                    remediation = issue.get("remedy_guidance", issue.get("remedy", ""))

                    dedup_key = f"{url}:{name}:{cwe_str}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    evidence_parts = [f"URL: {url}"]
                    if parameter:
                        evidence_parts.append(f"Param: {parameter}")
                    if cwe_str:
                        evidence_parts.append(f"CWE: {cwe_str}")
                    if remediation:
                        evidence_parts.append(f"Remediation: {remediation[:100]}")

                    findings.append(
                        {
                            "title": f"[{tag}] {name}",
                            "severity": severity,
                            "description": description[:200] if description else name,
                            "evidence": " | ".join(evidence_parts),
                            "tool": "arachni",
                            "target": url,
                            "timestamp": issue.get("generated_at", _now_iso()),
                        },
                    )
            except json.JSONDecodeError:
                pass

        for line in output.splitlines():
            line = line.strip()
            if not line or _JSON_RE.match(output):
                continue
            lower = line.lower()
            for sev in ("critical", "high", "medium", "low", "info"):
                if sev in lower:
                    dedup_key = f"text:{line[:100]}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": f"Arachni: {line[:80]}",
                            "severity": _SEVERITY_MAP.get(sev, "info"),
                            "description": line.strip()[:200],
                            "evidence": line.strip(),
                            "tool": "arachni",
                            "target": "unknown",
                            "timestamp": _now_iso(),
                        },
                    )
                    break

        return findings
