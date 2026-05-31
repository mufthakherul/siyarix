# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lightweight tool executor adapter for single-step tool runs."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

from .planner import ExecutionStep, StepResult, StepStatus


class ToolExecutor:
    """Execute a single tool step via an injected run function."""

    def __init__(
        self,
        resolver: Any = None,
        discovered_tools: list[Any] | None = None,
        run_tool_fn: Callable[..., Coroutine[Any, Any, Any]] | None = None,
    ) -> None:
        self._resolver = resolver
        self._tools = {getattr(t, "name", str(t)): t for t in (discovered_tools or [])}
        self._run_tool = run_tool_fn

    async def execute_step(
        self, step: ExecutionStep, interactive: bool = False
    ) -> StepResult:
        if self._resolver:
            resolved = self._resolver.resolve(step.tool, step.args)
            if not getattr(resolved, "is_safe", True):
                return StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED,
                    error="Tool is not safe",
                )
            path = getattr(resolved, "path", step.tool)
            args = getattr(resolved, "args", step.args)
        else:
            path = step.tool
            args = step.args

        if self._run_tool:
            result = await self._run_tool(path, args, timeout=300)
            exit_code = getattr(result, "exit_code", 0)
            stdout = getattr(result, "stdout", "")
            stderr = getattr(result, "stderr", "")
            if exit_code == 0:
                return StepResult(
                    step_id=step.id,
                    status=StepStatus.SUCCESS,
                    output=stdout,
                    exit_code=exit_code,
                )
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                output=stdout,
                error=stderr,
                exit_code=exit_code,
            )

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS,
            output=f"Executed {step.tool}",
        )
