# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data models for the planning system."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PlanStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"
    BLOCKED = "blocked"


class PlanType(StrEnum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    DAG = "dag"
    REACT = "react"
    ADAPTIVE = "adaptive"


class StepType(StrEnum):
    TOOL_RUN = "tool_run"
    SHELL_CMD = "shell_cmd"
    ANALYSIS = "analysis"
    REPORT = "report"
    NETWORK = "network"
    WEB = "web"


@dataclass
class ExecutionStep:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    step_type: StepType = StepType.TOOL_RUN
    tool: str = ""
    args: list[str] = field(default_factory=list)
    target: str = ""
    depends_on: list[str] = field(default_factory=list)
    command: str | None = None
    description: str = ""
    timeout: float = 300.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_plan_step(self) -> PlanStep:
        return PlanStep(
            id=self.id,
            description=self.description,
            tool=self.tool,
            args={"target": self.target} if self.target else {},
            command=self.command,
            dependencies=self.depends_on,
            timeout=self.timeout,
            metadata=self.metadata,
        )


@dataclass
class PlanStep:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    description: str = ""
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    command: str | None = None
    status: StepStatus = StepStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 300.0
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PlanStep):
            return NotImplemented
        return self.id == other.id

    @property
    def is_ready(self) -> bool:
        return self.status == StepStatus.PENDING

    @property
    def can_retry(self) -> bool:
        return self.retry_count < self.max_retries

    @property
    def is_terminal(self) -> bool:
        return self.status in (StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED)


@dataclass
class StepResult:
    step_id: str = ""
    status: StepStatus = StepStatus.PENDING
    output: str = ""
    error: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    exit_code: int | None = None
    duration_ms: float = 0.0


@dataclass
class ExecutionPlan:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    goal: str = ""
    plan_type: PlanType = PlanType.SEQUENTIAL
    status: PlanStatus = PlanStatus.DRAFT
    steps: list[PlanStep] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_instruction: str = ""
    source: str = ""
    confidence: float = 1.0

    @property
    def completed_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == StepStatus.COMPLETED]

    @property
    def failed_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == StepStatus.FAILED]

    @property
    def pending_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status in (StepStatus.PENDING, StepStatus.READY)]

    @property
    def is_complete(self) -> bool:
        return all(s.is_terminal for s in self.steps)

    @property
    def has_failures(self) -> bool:
        return any(s.status == StepStatus.FAILED for s in self.steps)

    @property
    def progress_pct(self) -> float:
        if not self.steps:
            return 100.0
        done = len(self.completed_steps) + len(
            [s for s in self.steps if s.status == StepStatus.SKIPPED]
        )
        return (done / len(self.steps)) * 100.0

    def get_step(self, step_id: str) -> PlanStep | None:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def get_ready_steps(self) -> list[PlanStep]:
        ready = []
        for step in self.steps:
            if step.status not in (StepStatus.PENDING, StepStatus.READY):
                continue
            deps_met = True
            for dep in step.dependencies:
                dep_step = self.get_step(dep)
                if dep_step is None or dep_step.status != StepStatus.COMPLETED:
                    deps_met = False
                    break
            if deps_met:
                step.status = StepStatus.READY
                ready.append(step)
        return ready

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "type": self.plan_type.value,
            "status": self.status.value,
            "progress": self.progress_pct,
            "steps": [
                {"id": s.id, "description": s.description, "tool": s.tool, "status": s.status.value}
                for s in self.steps
            ],
        }

__all__ = [
    "PlanStatus",
    "StepStatus",
    "PlanType",
    "StepType",
    "ExecutionStep",
    "PlanStep",
    "StepResult",
    "ExecutionPlan",
]
