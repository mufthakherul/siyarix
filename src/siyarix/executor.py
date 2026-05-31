# SPDX-License-Identifier: AGPL-3.0-or-later
"""Execution engine with guardrails, recovery, and tool dispatch."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from .planner import ExecutionPlan, PlanStep, StepStatus, PlanStatus
from .registry import ToolRegistry
from .events import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)
StepExecutor = Callable[[PlanStep], Coroutine[Any, Any, dict[str, Any]]]


@dataclass
class ExecutionBudget:
    max_iterations: int = 50
    max_tool_calls: int = 100
    max_duration_s: float = 600.0
    _iterations: int = field(default=0, repr=False)
    _tool_calls: int = field(default=0, repr=False)
    _start_time: float = field(default_factory=time.time, repr=False)

    @property
    def remaining_iterations(self) -> int:
        return max(0, self.max_iterations - self._iterations)

    @property
    def remaining_tool_calls(self) -> int:
        return max(0, self.max_tool_calls - self._tool_calls)

    @property
    def elapsed(self) -> float:
        return time.time() - self._start_time

    @property
    def is_exhausted(self) -> bool:
        return self._iterations >= self.max_iterations or self._tool_calls >= self.max_tool_calls or self.elapsed >= self.max_duration_s

    def consume_iteration(self) -> bool:
        if self.is_exhausted:
            return False
        self._iterations += 1
        return True

    def consume_tool_call(self) -> bool:
        if self.is_exhausted:
            return False
        self._tool_calls += 1
        return True


@dataclass
class GuardrailConfig:
    exact_failure_warn_after: int = 2
    exact_failure_block_after: int = 5
    same_tool_failure_halt_after: int = 8
    no_progress_block_after: int = 5


class ToolCallTracker:
    def __init__(self, config: GuardrailConfig | None = None) -> None:
        self._config = config or GuardrailConfig()
        self._failure_counts: dict[str, int] = {}
        self._consecutive_same: dict[str, int] = {}
        self._no_progress_count = 0
        self._last_mutation = ""

    def record(self, tool: str, args_key: str, success: bool) -> str | None:
        if success:
            self._failure_counts[tool] = 0
            self._no_progress_count = 0
            self._consecutive_same[tool] = 0
            self._last_mutation = f"{tool}:{args_key}"
        else:
            self._failure_counts[tool] = self._failure_counts.get(tool, 0) + 1
            if self._last_mutation == f"{tool}:{args_key}":
                self._no_progress_count += 1
            self._consecutive_same[tool] = self._consecutive_same.get(tool, 0) + 1
        if self._failure_counts.get(tool, 0) >= self._config.exact_failure_block_after:
            return f"BLOCKED: {tool} failed {self._failure_counts[tool]} times"
        if self._consecutive_same.get(tool, 0) >= self._config.same_tool_failure_halt_after:
            return f"HALTED: {tool} called {self._consecutive_same[tool]} times consecutively"
        if self._no_progress_count >= self._config.no_progress_block_after:
            return f"BLOCKED: No progress for {self._no_progress_count} calls"
        return None

    def reset(self) -> None:
        self._failure_counts.clear()
        self._consecutive_same.clear()
        self._no_progress_count = 0


class Executor:
    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry
        self._budget = ExecutionBudget()
        self._tracker = ToolCallTracker()
        self._custom_executors: dict[str, StepExecutor] = {}
        self._event_bus = get_event_bus()

    @property
    def budget(self) -> ExecutionBudget:
        return self._budget

    def register_executor(self, tool: str, executor: StepExecutor) -> None:
        self._custom_executors[tool] = executor

    async def execute_plan(self, plan: ExecutionPlan, executor_fn: StepExecutor | None = None) -> ExecutionPlan:
        plan.status = PlanStatus.ACTIVE
        await self._event_bus.emit(Event(type=EventType.PLAN_CREATED, source="executor",
            data={"plan_id": plan.id, "goal": plan.goal, "steps": len(plan.steps)}))
        while not plan.is_complete:
            if self._budget.is_exhausted:
                break
            ready_steps = plan.get_ready_steps()
            if not ready_steps:
                if plan.pending_steps:
                    blocked = all(
                        any(s.status == StepStatus.FAILED for s in plan.steps if s.id == dep)
                        for step in plan.pending_steps for dep in step.dependencies
                    )
                    if blocked:
                        break
                else:
                    break
                break
            if plan.plan_type.value in ("parallel", "dag"):
                await asyncio.gather(*[self._execute_step(s, executor_fn) for s in ready_steps], return_exceptions=True)
            else:
                await self._execute_step(ready_steps[0], executor_fn)
        plan.status = PlanStatus.COMPLETED if not plan.has_failures else PlanStatus.FAILED
        await self._event_bus.emit(Event(type=EventType.PLAN_COMPLETE, source="executor",
            data={"plan_id": plan.id, "status": plan.status.value, "progress": plan.progress_pct}))
        return plan

    async def _execute_step(self, step: PlanStep, executor_fn: StepExecutor | None) -> None:
        if not self._budget.consume_iteration():
            return
        step.status = StepStatus.RUNNING
        await self._event_bus.emit(Event(type=EventType.PLAN_STEP_START, source="executor",
            data={"step_id": step.id, "tool": step.tool}))
        start = time.time()
        try:
            if executor_fn:
                result = await executor_fn(step)
            elif step.tool in self._custom_executors:
                result = await self._custom_executors[step.tool](step)
            elif self._registry and step.tool:
                if not self._budget.consume_tool_call():
                    result = {"status": "error", "error": "Tool call budget exhausted"}
                else:
                    guardrail = self._tracker.record(step.tool, str(sorted(step.args.items())), True)
                    if guardrail and "BLOCKED" in guardrail:
                        result = {"status": "error", "error": guardrail}
                    else:
                        result = await self._registry.execute(step.tool, **step.args)
            else:
                result = {"status": "error", "error": f"No executor for: {step.tool}"}
            step.duration_ms = (time.time() - start) * 1000
            step.result = result
            if result.get("status") == "error":
                step.status = StepStatus.FAILED
                self._tracker.record(step.tool, str(sorted(step.args.items())), False)
                await self._event_bus.emit(Event(type=EventType.PLAN_STEP_FAILED, source="executor",
                    data={"step_id": step.id, "error": result.get("error", "")}))
            else:
                step.status = StepStatus.COMPLETED
                await self._event_bus.emit(Event(type=EventType.PLAN_STEP_COMPLETE, source="executor",
                    data={"step_id": step.id, "duration_ms": step.duration_ms}))
        except asyncio.CancelledError:
            step.status = StepStatus.SKIPPED
            raise
        except Exception as e:
            step.duration_ms = (time.time() - start) * 1000
            step.status = StepStatus.FAILED
            step.result = {"status": "error", "error": str(e)}
            self._tracker.record(step.tool, str(sorted(step.args.items())), False)

    def reset(self) -> None:
        self._budget = ExecutionBudget()
        self._tracker.reset()

    def stats(self) -> dict[str, Any]:
        return {"budget": {"iterations": self._budget._iterations, "tool_calls": self._budget._tool_calls, "elapsed_s": round(self._budget.elapsed, 1)},
                "tracker": {"failures": dict(self._tracker._failure_counts), "no_progress": self._tracker._no_progress_count}}
