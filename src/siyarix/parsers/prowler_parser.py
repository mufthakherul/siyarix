# SPDX-License-Identifier: AGPL-3.0-or-later

"""Prowler JSON output parser — extracts control checks with PASS/FAIL status, severity, region, and resource."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "muted": "info",
}


class ProwlerParser:
    """Parse Prowler JSON output (one JSON object per line) into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped or not _JSON_LINE_RE.match(line_stripped):
                continue

            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            control = obj.get("Control", obj.get("control", obj.get("control_id", "unknown")))
            status = obj.get("Status", obj.get("status", "")).upper()
            severity_raw = obj.get("Severity", obj.get("severity", "informational")).lower()
            region = obj.get("Region", obj.get("region", ""))
            resource_arn = obj.get("ResourceArn", obj.get("resource_arn", obj.get("arn", "")))

            severity = _SEVERITY_MAP.get(severity_raw, "info")

            if status == "PASS":
                severity = "info"

            dedup_key = f"{control}|{resource_arn or region}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            description = f"Prowler control {control} — {status}"
            if region:
                description += f" in {region}"
            if resource_arn:
                description += f" ({resource_arn})"

            evidence = f"Status: {status}, Region: {region}, Resource: {resource_arn}"
            target = resource_arn or region or control

            findings.append({
                "title": f"Prowler: {control} ({status})",
                "severity": severity,
                "description": description,
                "evidence": evidence,
                "tool": "prowler",
                "target": target,
                "timestamp": _now_iso(),
            })

        return findings
