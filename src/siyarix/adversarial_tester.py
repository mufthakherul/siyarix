# SPDX-License-Identifier: AGPL-3.0-or-later

"""Adversarial testing and plan validation module.

Analyzes AI-generated plans for potential issues before execution,
detecting IDS triggers, rate-limit violations, and other operational
risks as described in Chapter 16.3.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AdversarialSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AdversarialFinding:
    """A finding from adversarial plan review."""

    severity: AdversarialSeverity = AdversarialSeverity.INFO
    message: str = ""
    suggestion: str = ""
    related_tool: str = ""
    category: str = ""


# Known IDS-triggering patterns
_IDS_TRIGGER_PATTERNS: list[tuple[str, str, AdversarialSeverity]] = [
    (
        r"nmap\s+-s[CVW]",
        "Full connect/version scan may trigger IDS",
        AdversarialSeverity.MEDIUM,
    ),
    (
        r"masscan\s+--rate\s+10000",
        "High-rate masscan will likely trigger IDS",
        AdversarialSeverity.HIGH,
    ),
    (
        r"hydra\s+.*-l\s+root",
        "Rapid brute force will trigger account lockout",
        AdversarialSeverity.MEDIUM,
    ),
    (
        r"sqlmap\s+.*--batch",
        "Automated SQL injection without rate limiting",
        AdversarialSeverity.MEDIUM,
    ),
    (
        r"nuclei\s+.*-t\s+.*cves",
        "CVE scanning may trigger WAF detection",
        AdversarialSeverity.LOW,
    ),
    (
        r"gobuster\s+dir",
        "Directory brute-force may trigger rate limiting",
        AdversarialSeverity.LOW,
    ),
]


# Tool-specific risk mitigations
_TOOL_MITIGATIONS: dict[str, list[str]] = {
    "nmap": [
        "Consider adding -T2 for slower, stealthier scan",
        "Use -sS (SYN stealth) instead of -sV (version detection) for initial recon",
        "Add --randomize-hosts to randomize scan order",
    ],
    "masscan": [
        "Reduce rate with --rate 1000 to avoid network congestion",
        "Use --randomize-hosts for distributed scanning pattern",
    ],
    "ffuf": [
        "Add -rate 100 to limit requests per second",
        "Use -ac to filter false positives automatically",
    ],
    "nuclei": [
        "Consider using -rl 50 to rate limit requests",
        "Use -H headers to blend in with normal traffic",
    ],
    "hydra": [
        "Add -t 2 to limit parallel tasks",
        "Add -W 5 to increase wait time between attempts",
    ],
    "sqlmap": [
        "Use --delay 2 to add delay between requests",
        "Use --random-agent to randomize User-Agent",
    ],
}


class AdversarialTester:
    """Adversarial plan analysis and risk detection engine."""

    def __init__(self) -> None:
        self._review_history: list[dict[str, Any]] = []

    def review_plan(self, plan_lines: list[str]) -> list[AdversarialFinding]:
        findings: list[AdversarialFinding] = []
        full_plan = " ".join(plan_lines)

        # 1) IDS trigger detection
        for pattern, message, severity in _IDS_TRIGGER_PATTERNS:
            if re.search(pattern, full_plan, re.IGNORECASE):
                tool = (
                    pattern.split(r"\s+")[0]
                    if pattern.startswith(r"nmap")
                    else "unknown"
                )
                findings.append(
                    AdversarialFinding(
                        severity=severity,
                        message=message,
                        suggestion=(
                            self._get_mitigation(tool) if tool != "unknown" else ""
                        ),
                        related_tool=tool,
                        category="ids_trigger",
                    )
                )

        # 2) Rate limiting detection
        rate_findings = self._detect_rate_issues(plan_lines)
        findings.extend(rate_findings)

        # 3) Safety checks
        safety_findings = self._detect_safety_issues(full_plan)
        findings.extend(safety_findings)

        # 4) Dependency issues
        dep_findings = self._detect_dependency_issues(plan_lines)
        findings.extend(dep_findings)

        self._review_history.append(
            {
                "plan": plan_lines,
                "findings_count": len(findings),
                "critical_count": sum(
                    1 for f in findings if f.severity == AdversarialSeverity.CRITICAL
                ),
                "high_count": sum(
                    1 for f in findings if f.severity == AdversarialSeverity.HIGH
                ),
            }
        )

        return findings

    def _detect_rate_issues(self, plan_lines: list[str]) -> list[AdversarialFinding]:
        findings: list[AdversarialFinding] = []
        aggressive_tools_without_limit = {
            "masscan": 0,
            "hydra": 0,
            "ffuf": 0,
            "sqlmap": 0,
        }

        for line in plan_lines:
            for tool in aggressive_tools_without_limit:
                if tool in line.lower():
                    aggressive_tools_without_limit[tool] += 1

        for tool, count in aggressive_tools_without_limit.items():
            if count > 0:
                mitigations = _TOOL_MITIGATIONS.get(tool, [])
                if mitigations:
                    findings.append(
                        AdversarialFinding(
                            severity=AdversarialSeverity.LOW,
                            message=f"{tool} used without explicit rate limiting",
                            suggestion=mitigations[0],
                            related_tool=tool,
                            category="rate_limiting",
                        )
                    )

        return findings

    def _detect_safety_issues(self, full_plan: str) -> list[AdversarialFinding]:
        findings: list[AdversarialFinding] = []
        danger_patterns = [
            (
                r"(rm\s+-rf|mkfs|dd\s+if=)",
                "Destructive command detected in plan",
                AdversarialSeverity.CRITICAL,
                "Remove destructive commands from automated plan",
            ),
            (
                r"(DROP\s+TABLE|DELETE\s+FROM)",
                "Destructive SQL statement detected",
                AdversarialSeverity.HIGH,
                "Use SELECT for verification instead",
            ),
            (
                r"(chmod\s+777|chmod\s+-R\s+777)",
                "Overly permissive file permissions",
                AdversarialSeverity.MEDIUM,
                "Use least-privilege permissions",
            ),
        ]
        for pattern, message, severity, suggestion in danger_patterns:
            if re.search(pattern, full_plan, re.IGNORECASE):
                findings.append(
                    AdversarialFinding(
                        severity=severity,
                        message=message,
                        suggestion=suggestion,
                        category="safety",
                    )
                )
        return findings

    def _detect_dependency_issues(
        self, plan_lines: list[str]
    ) -> list[AdversarialFinding]:
        findings: list[AdversarialFinding] = []
        tool_mentions: dict[str, int] = {}
        for line in plan_lines:
            for tool in _TOOL_MITIGATIONS:
                if tool in line.lower():
                    tool_mentions[tool] = tool_mentions.get(tool, 0) + 1

        dependencies = {
            "nuclei": ["nmap"],
            "gobuster": ["nmap"],
            "sqlmap": ["nmap"],
        }
        for tool, required in dependencies.items():
            if tool in tool_mentions:
                missing = [r for r in required if r not in tool_mentions]
                if missing:
                    findings.append(
                        AdversarialFinding(
                            severity=AdversarialSeverity.LOW,
                            message=f"Plan uses {tool} but missing preceding {', '.join(missing)} scan",
                            suggestion=f"Consider adding {', '.join(missing)} scan before {tool}",
                            related_tool=tool,
                            category="dependency",
                        )
                    )
        return findings

    def _get_mitigation(self, tool: str) -> str:
        mitigations = _TOOL_MITIGATIONS.get(tool, [])
        return mitigations[0] if mitigations else ""

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        return self._review_history[-limit:]

    def summary(self) -> dict[str, Any]:
        return {
            "total_reviews": len(self._review_history),
            "total_findings": sum(r["findings_count"] for r in self._review_history),
            "critical_findings": sum(r["critical_count"] for r in self._review_history),
            "high_findings": sum(r["high_count"] for r in self._review_history),
        }


__all__ = ["AdversarialTester", "AdversarialFinding", "AdversarialSeverity"]
