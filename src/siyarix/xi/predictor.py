# SPDX-License-Identifier: AGPL-3.0-or-later

"""XI Predictor — Predictive action engine for Siyarix.

Analyzes user behaviour patterns and current context to suggest:
  • Next likely command
  • Recommended tools based on phase
  • Follow-up actions after findings
  • Risk-aware workflow suggestions
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Predictor", "Prediction"]

logger = logging.getLogger(__name__)


@dataclass
class Prediction:
    """A predicted next action."""

    action: str
    confidence: float  # 0.0 → 1.0
    reason: str
    category: str = "suggestion"  # suggestion | warning | optimization
    metadata: dict[str, Any] = field(default_factory=dict)


# Phase → recommended follow-up actions
_PHASE_ACTIONS: dict[str, list[tuple[str, str]]] = {
    "idle": [
        ("nmap -sn {target}", "Start with host discovery"),
        ("whois {target}", "Gather domain registration info"),
    ],
    "recon": [
        ("nmap -sV -sC {target}", "Service version detection scan"),
        ("subfinder -d {target}", "Subdomain enumeration"),
        ("dig {target} ANY", "DNS record enumeration"),
    ],
    "scanning": [
        ("nuclei -u {target}", "Vulnerability scanning with Nuclei"),
        ("nikto -h {target}", "Web server scanner"),
        ("gobuster dir -u http://{target}", "Directory brute-force"),
    ],
    "enumeration": [
        ("sqlmap -u http://{target}", "SQL injection testing"),
        ("wpscan --url http://{target}", "WordPress vulnerability scan"),
        ("ffuf -u http://{target}/FUZZ", "Fuzzing for hidden endpoints"),
    ],
    "exploitation": [
        ("hydra -L users.txt -P pass.txt {target} ssh", "Brute-force SSH credentials"),
        ("report the findings", "Document exploitation results"),
    ],
    "post_exploitation": [
        ("generate report", "Create a comprehensive findings report"),
        ("export findings to JSON", "Export structured findings data"),
    ],
    "reporting": [
        ("siyarix report generate", "Generate final report"),
        ("siyarix history list", "Review scan history"),
    ],
}

# Tool → follow-up suggestions
_TOOL_FOLLOWUPS: dict[str, list[tuple[str, str]]] = {
    "nmap": [
        ("nuclei -u {target}", "Scan discovered services for vulns"),
        ("gobuster dir -u http://{target}", "Enumerate web directories"),
    ],
    "nuclei": [
        ("report the findings", "Compile vulnerability report"),
        ("sqlmap -u {target}", "Test for SQL injection on findings"),
    ],
    "gobuster": [
        ("nikto -h {target}", "Deeper web server analysis"),
        ("ffuf -u http://{target}/FUZZ", "Extended fuzzing"),
    ],
    "nikto": [
        ("nuclei -u {target}", "Cross-reference with Nuclei templates"),
    ],
    "whois": [
        ("dig {target} ANY", "Full DNS enumeration"),
        ("nmap -sV {target}", "Port and service scan"),
    ],
}


class Predictor:
    """Predictive action engine for Siyarix XI."""

    def __init__(self) -> None:
        self._command_patterns: Counter[str] = Counter()
        self._sequence_pairs: Counter[tuple[str, str]] = Counter()
        self._last_command: str = ""

    def learn(self, command: str) -> None:
        """Learn from a user command to improve predictions."""
        # Extract tool name
        tool = command.strip().split()[0] if command.strip() else ""
        self._command_patterns[tool] += 1
        if self._last_command:
            self._sequence_pairs[(self._last_command, tool)] += 1
        self._last_command = tool

    def predict_next(
        self,
        phase: str,
        last_tool: str = "",
        target: str = "",
        findings_count: int = 0,
    ) -> list[Prediction]:
        """Generate predictions for the next action."""
        predictions: list[Prediction] = []

        # 1) Phase-based recommendations
        phase_actions = _PHASE_ACTIONS.get(phase, _PHASE_ACTIONS.get("idle", []))
        for action_template, reason in phase_actions[:3]:
            action = (
                action_template.replace("{target}", target)
                if target
                else action_template
            )
            predictions.append(
                Prediction(
                    action=action,
                    confidence=0.7,
                    reason=f"Phase [{phase}]: {reason}",
                    category="suggestion",
                )
            )

        # 2) Tool follow-up recommendations
        if last_tool:
            followups = _TOOL_FOLLOWUPS.get(last_tool.lower(), [])
            for action_template, reason in followups[:2]:
                action = (
                    action_template.replace("{target}", target)
                    if target
                    else action_template
                )
                predictions.append(
                    Prediction(
                        action=action,
                        confidence=0.8,
                        reason=f"After {last_tool}: {reason}",
                        category="suggestion",
                    )
                )

        # 3) Findings-based recommendations
        if findings_count > 0:
            predictions.append(
                Prediction(
                    action="generate report" if target else "siyarix report generate",
                    confidence=0.6,
                    reason=f"{findings_count} finding(s) detected — consider reporting",
                    category="suggestion",
                )
            )

        # 4) Learned pattern-based predictions
        if self._last_command:
            for (prev, nxt), count in self._sequence_pairs.most_common(3):
                if prev == self._last_command and count >= 2:
                    predictions.append(
                        Prediction(
                            action=nxt,
                            confidence=min(0.5 + count * 0.1, 0.9),
                            reason=f"You frequently run {nxt} after {prev}",
                            category="optimization",
                            metadata={"pattern_count": count},
                        )
                    )

        # 5) Warning if idle too long in active phase
        if phase not in ("idle", "reporting", "cleanup") and findings_count == 0:
            predictions.append(
                Prediction(
                    action="review approach",
                    confidence=0.4,
                    reason="No findings yet in active phase — consider adjusting approach",
                    category="warning",
                )
            )

        # Deduplicate by action
        seen: set[str] = set()
        unique: list[Prediction] = []
        for p in predictions:
            if p.action not in seen:
                seen.add(p.action)
                unique.append(p)

        # Sort by confidence descending
        unique.sort(key=lambda p: p.confidence, reverse=True)
        return unique[:8]

    def reset(self) -> None:
        """Reset learned patterns."""
        self._command_patterns.clear()
        self._sequence_pairs.clear()
        self._last_command = ""
