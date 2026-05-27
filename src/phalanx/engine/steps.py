"""Engine step types, result tracking, and execution mode constants."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..engine_types import StepResult, StepStatus

_MAX_CONTEXT_OUTPUT_LENGTH = 2000

_MAX_RETRIES = 3
_RETRY_BACKOFF_FACTOR = 2.0
_RETRY_BASE_DELAY = 1.0
_RETRY_MAX_DELAY = 30.0


class ExecutionMode(StrEnum):
    """Execution mode for the engine."""

    REGISTRY = "registry"
    AUTONOMOUS = "autonomous"
    INTEGRATED = "integrated"


@dataclass
class EngineResult:
    """Aggregate result of executing an entire plan."""

    plan: Any  # ExecutionPlan — forward ref to avoid circular import
    step_results: list[StepResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    mode: ExecutionMode = ExecutionMode.INTEGRATED
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    plan_id: str | None = None
    retries_performed: int = 0

    @property
    def success(self) -> bool:
        return all(
            r.status in (StepStatus.SUCCESS, StepStatus.SKIPPED)
            for r in self.step_results
        )

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.step_results:
            counts[r.status.value] = counts.get(r.status.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "plan": self.plan.to_dict(),
            "step_results": [
                {
                    "step_id": r.step_id,
                    "status": r.status.value,
                    "output": r.output[:1000],
                    "error": r.error,
                    "duration_ms": r.duration_ms,
                    "findings": r.findings,
                    "retry_count": r.retry_count,
                    "exit_code": r.exit_code,
                }
                for r in self.step_results
            ],
            "total_duration_ms": self.total_duration_ms,
            "mode": self.mode.value,
            "success": self.success,
            "retries_performed": self.retries_performed,
        }
