# SPDX-License-Identifier: AGPL-3.0-or-later

"""ScoutSuite cloud auditing output parser — parses ScoutSuite JSON results."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")


class ScoutsuiteParser:
    """Parse ScoutSuite JSON report into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        if not _JSON_RE.match(output):
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        seen: set[str] = set()

        aws_account_id = data.get(
            "aws_account_id",
            data.get("azure_subscription_id", data.get("gcp_project_id", "unknown")),
        )
        provider = (
            "aws"
            if "aws_account_id" in data
            else "azure"
            if "azure_subscription_id" in data
            else "gcp"
            if "gcp_project_id" in data
            else "cloud"
        )

        services = data.get("services", {})
        if isinstance(services, dict):
            for service_data in services.values():
                findings_data = service_data.get("findings", {})
                if isinstance(findings_data, dict):
                    for finding_key, finding_data in findings_data.items():
                        if isinstance(finding_data, dict):
                            self._extract_finding(
                                finding_key,
                                finding_data,
                                provider,
                                aws_account_id,
                                findings,
                                seen,
                            )

        rulesets = data.get("rule_results", {})
        if isinstance(rulesets, dict):
            for rule_id, rule_data in rulesets.items():
                if isinstance(rule_data, dict):
                    items = rule_data.get("items", [])
                    if isinstance(items, list):
                        for item in items:
                            dedup_key = f"{rule_id}|{item}"
                            if dedup_key in seen:
                                continue
                            seen.add(dedup_key)
                            findings.append(
                                {
                                    "title": f"ScoutSuite: {rule_id}",
                                    "severity": rule_data.get("level", "info"),
                                    "description": f"ScoutSuite rule {rule_id} applied to {item}",
                                    "evidence": f"Rule: {rule_id} | Resource: {item}",
                                    "tool": "scoutsuite",
                                    "target": str(aws_account_id),
                                    "timestamp": _now_iso(),
                                },
                            )

        return findings

    def _extract_finding(
        self,
        key: str,
        data: dict,
        provider: str,
        account_id: str,
        findings: list,
        seen: set,
    ) -> None:
        description = data.get("description", data.get("dashboard_name", key))
        severity_str = data.get("severity", data.get("level", "info")).lower()
        severity = (
            severity_str
            if severity_str in ("critical", "high", "medium", "low", "info")
            else "info"
        )
        service = data.get("service", provider)
        region = data.get("region", "global")
        items = data.get("items", data.get("resources", []))
        if isinstance(items, list) and len(items) > 0:
            for item in items[:10]:
                dedup_key = f"{key}|{item}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"[{service}] {description[:60]}",
                        "severity": severity,
                        "description": str(description)[:200],
                        "evidence": f"Resource: {item} | Region: {region}",
                        "tool": "scoutsuite",
                        "target": str(account_id),
                        "timestamp": _now_iso(),
                    },
                )
        elif items:
            dedup_key = f"{key}|{service}|{region}"
            if dedup_key in seen:
                return
            seen.add(dedup_key)
            findings.append(
                {
                    "title": f"[{service}] {str(description)[:60]}",
                    "severity": severity,
                    "description": str(description)[:200],
                    "evidence": f"Service: {service} | Region: {region}",
                    "tool": "scoutsuite",
                    "target": str(account_id),
                    "timestamp": _now_iso(),
                },
            )
