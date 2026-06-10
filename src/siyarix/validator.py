# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-validation, verification, and recovery system."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable

from .planner import PlanStep
from .events import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)


class ValidationSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RecoveryAction(StrEnum):
    RETRY = "retry"
    RETRY_ALTERNATIVE = "retry_alternative"
    SKIP = "skip"
    ABORT = "abort"
    ESCALATE = "escalate"
    DEGRADE = "degrade"


@dataclass
class ValidationResult:
    passed: bool = True
    severity: ValidationSeverity = ValidationSeverity.INFO
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    recovery_action: RecoveryAction | None = None
    recovery_suggestion: str = ""


@dataclass
class RecoveryPlan:
    original_step: PlanStep
    action: RecoveryAction
    modified_step: PlanStep | None = None
    alternative_tool: str = ""
    message: str = ""


class Validator:
    def __init__(self) -> None:
        self._validators: list[Callable[[PlanStep], ValidationResult]] = [
            self._validate_step_has_tool, self._validate_step_has_args, self._validate_step_timeout,
        ]
        self._event_bus = get_event_bus()
        self._results: list[ValidationResult] = []

    def _validate_step_has_tool(self, step: PlanStep) -> ValidationResult:
        if not step.tool:
            return ValidationResult(passed=False, severity=ValidationSeverity.ERROR,
                message="Step has no tool specified", recovery_action=RecoveryAction.SKIP)
        return ValidationResult(passed=True)

    def _validate_step_has_args(self, step: PlanStep) -> ValidationResult:
        if not step.args and step.tool not in ("report", "summary"):
            return ValidationResult(passed=False, severity=ValidationSeverity.WARNING,
                message=f"Step '{step.tool}' has no arguments", recovery_action=RecoveryAction.RETRY)
        return ValidationResult(passed=True)

    def _validate_step_timeout(self, step: PlanStep) -> ValidationResult:
        if step.timeout <= 0:
            return ValidationResult(passed=False, severity=ValidationSeverity.WARNING,
                message="Step timeout is non-positive", recovery_action=RecoveryAction.RETRY)
        return ValidationResult(passed=True)

    async def validate_step(self, step: PlanStep) -> list[ValidationResult]:
        results = [v(step) for v in self._validators]
        for r in results:
            if not r.passed:
                await self._event_bus.emit(Event(type=EventType.VALIDATION_FAILED, source="validator",
                    data={"step_id": step.id, "tool": step.tool, "message": r.message}))
        self._results.extend(results)
        return results

    async def validate_plan(self, steps: list[PlanStep]) -> list[ValidationResult]:
        all_results = []
        for step in steps:
            all_results.extend(await self.validate_step(step))
        return all_results

    async def plan_recovery(self, step: PlanStep, error: str) -> RecoveryPlan:
        tool = step.tool
        if tool == "nmap" and "filtered" in error.lower():
            return RecoveryPlan(original_step=step, action=RecoveryAction.RETRY,
                modified_step=PlanStep(id=step.id, description=step.description, tool=tool,
                    args={**step.args, "flags": step.args.get("flags", "") + " -Pn"}, timeout=step.timeout),
                message="Adding -Pn flag for filtered ports")
        if tool in ("nikto", "nuclei") and "refused" in error.lower():
            return RecoveryPlan(original_step=step, action=RecoveryAction.RETRY_ALTERNATIVE,
                alternative_tool="nuclei" if tool == "nikto" else "nikto",
                message="Target refused connection, trying alternative")
        if tool in ("gobuster", "ffuf") and "404" in error:
            return RecoveryPlan(original_step=step, action=RecoveryAction.RETRY,
                modified_step=PlanStep(id=step.id, description=step.description, tool=tool,
                    args={**step.args, "extensions": "php,html,js,txt,asp,aspx,jsp"}, timeout=step.timeout),
                message="Adding more file extensions")
        if step.can_retry:
            return RecoveryPlan(original_step=step, action=RecoveryAction.RETRY,
                message=f"Retrying (attempt {step.retry_count + 1}/{step.max_retries})")
        return RecoveryPlan(original_step=step, action=RecoveryAction.SKIP,
            message=f"Max retries exceeded for {tool}")

    def stats(self) -> dict[str, Any]:
        return {"total_validations": len(self._results), "passed": len([r for r in self._results if r.passed]),
                "failed": len([r for r in self._results if not r.passed])}
