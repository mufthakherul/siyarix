"""Intent routing for mode selection and risk-aware execution hints."""

from __future__ import annotations

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


class IntentRouter:
    """Classify command intent and return execution hints."""

    def __init__(self) -> None:
        self._interpreter = RuleInterpreter()

    def route(self, instruction: str, preferred_mode: str = "integrated") -> IntentRoute:
        task = self._interpreter.interpret(instruction)
        risk_tier = self._risk_from_category(task.category)
        requires_confirmation = risk_tier in {RiskTier.MEDIUM, RiskTier.HIGH}
        selected_mode = preferred_mode
        if task.category == TaskCategory.UNKNOWN and preferred_mode == "registry":
            selected_mode = "integrated"

        return IntentRoute(
            instruction=instruction,
            mode=selected_mode,
            category=task.category.value,
            confidence=task.confidence,
            risk_tier=risk_tier,
            requires_confirmation=requires_confirmation,
            metadata={
                "targets": task.targets,
                "tools": task.tools,
                "flags": task.flags,
            },
        )

    def _risk_from_category(self, category: TaskCategory) -> RiskTier:
        if category in {TaskCategory.EXPLOIT, TaskCategory.CLOUD, TaskCategory.CONFIG}:
            return RiskTier.HIGH
        if category in {TaskCategory.SCAN, TaskCategory.RECON, TaskCategory.WORKFLOW}:
            return RiskTier.MEDIUM
        return RiskTier.LOW

