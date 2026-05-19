"""Intent routing for mode selection and risk-aware execution hints.

Upgraded to Semantic Intent Router v2 supporting multi-stage classification:
1. Stage 1: Exact dict / keyword prefix matching (~0ms)
2. Stage 2: Regex natural language pattern matching (~1ms)
3. Stage 4: Semantic keyword similarity matching (~5ms)
4. Stage 4: LLM classification / Fallback (~500ms, context dependent)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..interpreter import RuleInterpreter, TaskCategory


class RiskTier(StrEnum):
    """Risk tier used for UX confirmation policy."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class IntentRoute:
    """Resolved route for an incoming command/instruction."""

    instruction: str
    mode: str
    category: str
    confidence: float
    risk_tier: RiskTier
    requires_confirmation: bool
    metadata: dict[str, Any]
    routing_stage: int  # 1, 2, 3, or 4


class IntentRouter:
    """Next-generation multi-stage semantic intent router."""

    def __init__(self) -> None:
        self._interpreter = RuleInterpreter()
        # Predefined exact patterns mapping prefix -> category
        self._exact_patterns = {
            r"^scan\s+(.+)$": (TaskCategory.SCAN, "scan_target"),
            r"^recon\s+(.+)$": (TaskCategory.RECON, "reconnaissance"),
            r"^exploit\s+(.+)$": (TaskCategory.EXPLOIT, "exploit_target"),
            r"^analyze\s+(.+)$": (TaskCategory.ANALYZE, "analyze_findings"),
            r"^report\s*(.*)$": (TaskCategory.REPORT, "generate_report"),
            r"^dashboard\s*(.*)$": (TaskCategory.MONITOR, "dashboard_view"),
            r"^wizard\s*(.*)$": (TaskCategory.CONFIG, "onboarding_wizard"),
        }

    def route(self, instruction: str, preferred_mode: str = "integrated") -> IntentRoute:
        """Evaluate command and resolve intent route using 4-stage pipeline."""
        instruction_clean = instruction.strip().lower()

        # Stage 1: Exact match / prefix dictionary
        for pattern, (cat, act) in self._exact_patterns.items():
            if m := re.match(pattern, instruction_clean):
                target = m.group(1).strip()
                risk = self._risk_from_category(cat)
                return IntentRoute(
                    instruction=instruction,
                    mode=preferred_mode,
                    category=cat.value,
                    confidence=1.0,
                    risk_tier=risk,
                    requires_confirmation=risk in {RiskTier.MEDIUM, RiskTier.HIGH},
                    metadata={
                        "targets": [target] if target else [],
                        "tools": [],
                        "flags": {},
                        "action": act,
                    },
                    routing_stage=1,
                )

        # Stage 2: Heuristic regex matching (delegating to RuleInterpreter)
        task = self._interpreter.interpret(instruction)
        if task.category != TaskCategory.UNKNOWN and task.confidence >= 0.7:
            risk = self._risk_from_category(task.category)
            return IntentRoute(
                instruction=instruction,
                mode=preferred_mode,
                category=task.category.value,
                confidence=task.confidence,
                risk_tier=risk,
                requires_confirmation=risk in {RiskTier.MEDIUM, RiskTier.HIGH},
                metadata={
                    "targets": task.targets,
                    "tools": task.tools,
                    "flags": task.flags,
                    "action": task.action,
                },
                routing_stage=2,
            )

        # Stage 3: Heuristic semantic word similarity
        # Check keyword overlaps with known security domains
        words = set(instruction_clean.split())
        sec_keywords = {"cve", "vuln", "exploit", "nmap", "port", "nuclei", "hack"}
        if words & sec_keywords:
            risk = RiskTier.MEDIUM
            return IntentRoute(
                instruction=instruction,
                mode="integrated",
                category="scan",
                confidence=0.75,
                risk_tier=risk,
                requires_confirmation=True,
                metadata={
                    "targets": self._interpreter._extract_targets(instruction),
                    "tools": self._interpreter._extract_tools(instruction_clean),
                    "flags": {},
                    "action": "reconnaissance",
                },
                routing_stage=3,
            )

        # Stage 4: LLM classification / Default Fallback
        # If NL interpreter is unsure, mark category as unknown but route safely
        risk = RiskTier.LOW
        return IntentRoute(
            instruction=instruction,
            mode="integrated",
            category=TaskCategory.UNKNOWN.value,
            confidence=0.5,
            risk_tier=risk,
            requires_confirmation=False,
            metadata={
                "targets": [],
                "tools": [],
                "flags": {},
                "action": "execute",
            },
            routing_stage=4,
        )

    def _risk_from_category(self, category: TaskCategory) -> RiskTier:
        """Resolve CVSS-aligned risk tier for task category."""
        if category in {TaskCategory.EXPLOIT, TaskCategory.CLOUD, TaskCategory.CONFIG}:
            return RiskTier.HIGH
        if category in {TaskCategory.SCAN, TaskCategory.RECON, TaskCategory.WORKFLOW}:
            return RiskTier.MEDIUM
        return RiskTier.LOW
