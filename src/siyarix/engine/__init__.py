# SPDX-License-Identifier: AGPL-3.0-or-later

"""Execution engine package.

Re-exports everything from the original engine module for API compatibility.
"""

from __future__ import annotations

from ..engine_types import StepResult, StepStatus
from ..executor import run_tool_complete
from ..planner import ExecutionStep

from .executor import ExecutionEngine, logger
from .steps import (
    EngineResult,
    ExecutionMode,
)

__all__ = [
    "EngineResult",
    "ExecutionEngine",
    "ExecutionMode",
    "ExecutionStep",
    "StepResult",
    "StepStatus",
    "logger",
    "run_tool_complete",
]
