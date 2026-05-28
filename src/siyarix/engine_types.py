# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared engine types used by ExecutionEngine and ToolExecutor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass
class StepResult:
    step_id: str
    status: StepStatus
    output: str = ""
    error: str = ""
    duration_ms: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    exit_code: int | None = None


__all__ = ["StepStatus", "StepResult"]
