# SPDX-License-Identifier: AGPL-3.0-or-later
"""Execution engine with guardrails, recovery, and tool dispatch."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from .planner import ExecutionPlan, PlanStep, StepStatus, PlanStatus
from .registry import RiskLevel, ToolRegistry
from .events import Event, EventType, get_event_bus
from .worker_pool import AsyncWorkerPool
from .exceptions import PermissionDeniedError
from .permission_gate import PermissionGate

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
        return (
            self._iterations >= self.max_iterations
            or self._tool_calls >= self.max_tool_calls
            or self.elapsed >= self.max_duration_s
        )

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


StepCallback = Callable[[PlanStep], None]


class Executor:
    def __init__(
        self,
        registry: ToolRegistry | None = None,
        max_workers: int = 10,
        permission_gate: PermissionGate | None = None,
    ) -> None:
        self._registry = registry
        self._budget = ExecutionBudget()
        self._tracker = ToolCallTracker()
        self._custom_executors: dict[str, StepExecutor] = {}
        self._event_bus = get_event_bus()
        self._pool = AsyncWorkerPool(max_workers=max_workers)
        self._on_step_progress: StepCallback | None = None
        self._permission_gate = permission_gate

    def set_progress_callback(self, cb: StepCallback | None) -> None:
        self._on_step_progress = cb

    @property
    def budget(self) -> ExecutionBudget:
        return self._budget

    def register_executor(self, tool: str, executor: StepExecutor) -> None:
        self._custom_executors[tool] = executor

    async def execute_plan(
        self, plan: ExecutionPlan, executor_fn: StepExecutor | None = None
    ) -> ExecutionPlan:
        plan.status = PlanStatus.ACTIVE
        await self._event_bus.emit(
            Event(
                type=EventType.PLAN_CREATED,
                source="executor",
                data={"plan_id": plan.id, "goal": plan.goal, "steps": len(plan.steps)},
            )
        )
        while not plan.is_complete:
            if self._budget.is_exhausted:
                break
            ready_steps = plan.get_ready_steps()
            if not ready_steps:
                if plan.pending_steps:
                    blocked = all(
                        any(s.status == StepStatus.FAILED for s in plan.steps if s.id == dep)
                        for step in plan.pending_steps
                        for dep in step.dependencies
                    )
                    if blocked:
                        break
                else:
                    break
                break
            # Auto-parallel: run independent steps concurrently
            can_parallel = plan.plan_type.value in ("parallel", "dag") or (
                plan.plan_type.value == "sequential"
                and len(ready_steps) > 1
                and all(not s.dependencies for s in ready_steps)
            )
            if can_parallel:
                tasks = [self._pool.submit(self._execute_step, s, executor_fn) for s in ready_steps]
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                for s in ready_steps:
                    await self._execute_step(s, executor_fn)
                    if self._budget.is_exhausted:
                        break
        plan.status = PlanStatus.COMPLETED if not plan.has_failures else PlanStatus.FAILED
        await self._event_bus.emit(
            Event(
                type=EventType.PLAN_COMPLETE,
                source="executor",
                data={
                    "plan_id": plan.id,
                    "status": plan.status.value,
                    "progress": plan.progress_pct,
                },
            )
        )
        return plan

    async def _execute_step(self, step: PlanStep, executor_fn: StepExecutor | None) -> None:
        if not self._budget.consume_iteration():
            return
        step.status = StepStatus.RUNNING
        await self._event_bus.emit(
            Event(
                type=EventType.PLAN_STEP_START,
                source="executor",
                data={"step_id": step.id, "tool": step.tool},
            )
        )
        if self._on_step_progress:
            self._on_step_progress(step)
        start = time.time()
        try:
            result = await self._try_execute(step, executor_fn)
            step.duration_ms = (time.time() - start) * 1000
            step.result = result
            if result.get("status") == "error":
                step.status = StepStatus.FAILED
                self._tracker.record(step.tool, str(sorted(step.args.items())), False)
                await self._event_bus.emit(
                    Event(
                        type=EventType.PLAN_STEP_FAILED,
                        source="executor",
                        data={"step_id": step.id, "error": result.get("error", "")},
                    )
                )
            else:
                step.status = StepStatus.COMPLETED
                await self._event_bus.emit(
                    Event(
                        type=EventType.PLAN_STEP_COMPLETE,
                        source="executor",
                        data={"step_id": step.id, "duration_ms": step.duration_ms},
                    )
                )
        except asyncio.CancelledError:
            step.status = StepStatus.SKIPPED
            raise
        except Exception as e:
            step.duration_ms = (time.time() - start) * 1000
            step.status = StepStatus.FAILED
            step.result = {"status": "error", "error": str(e)}
            self._tracker.record(step.tool, str(sorted(step.args.items())), False)
        if self._on_step_progress:
            self._on_step_progress(step)

    async def _try_execute(
        self, step: PlanStep, executor_fn: StepExecutor | None
    ) -> dict[str, Any]:
        from .planner import TOOL_ALTERNATIVES

        if executor_fn:
            return await executor_fn(step)
        if step.tool in self._custom_executors:
            return await self._custom_executors[step.tool](step)
        if self._registry and step.tool:
            # ── Permission Gate ──
            if self._permission_gate:
                await self._check_permissions(step)
            # ── Budget & Execute ──
            if not self._budget.consume_tool_call():
                return {"status": "error", "error": "Tool call budget exhausted"}
            guardrail = self._tracker.record(step.tool, str(sorted(step.args.items())), True)
            if guardrail and "BLOCKED" in guardrail:
                return {"status": "error", "error": guardrail}
            result = await self._registry.execute(step.tool, **step.args)
            if result.get("status") == "error":
                alt_tools = TOOL_ALTERNATIVES.get(step.tool, [])
                for alt in alt_tools:
                    if alt in self._custom_executors or (
                        self._registry and self._registry.graph.get_tool(alt)
                    ):
                        guardrail = self._tracker.record(alt, str(sorted(step.args.items())), True)
                        if guardrail and "BLOCKED" in guardrail:
                            continue
                        alt_result = await self._registry.execute(alt, **step.args)
                        if alt_result.get("status") != "error":
                            step.tool = alt
                            return alt_result
            return result
        return {"status": "error", "error": f"No executor for: {step.tool}"}

    async def _check_permissions(self, step: PlanStep) -> None:
        command = step.command or step.args.get("command", "")
        tool_cap = self._registry.graph.get_tool(step.tool) if self._registry else None

        if command:
            gate_result = self._permission_gate.check(command, tool=step.tool)
            if not gate_result.allowed:
                self._log_safety(step.tool, command, "blocked", gate_result.reason)
                raise PermissionDeniedError(gate_result.reason)
            if gate_result.requires_review:
                from .shell_review import review_and_confirm

                reviewed = review_and_confirm(command, step.tool, gate_result.reason)
                if reviewed is None:
                    self._log_safety(step.tool, command, "cancelled", "User cancelled")
                    raise PermissionDeniedError(f"Cancelled by user: {gate_result.reason}")
                if reviewed != command:
                    step.command = reviewed
                    if "command" in step.args:
                        step.args["command"] = reviewed
                self._log_safety(step.tool, command, "approved", gate_result.reason)

        if tool_cap and tool_cap.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            from .shell_review import review_and_confirm

            summary = f"{step.tool} {' '.join(str(v) for v in step.args.values())}"
            reviewed = review_and_confirm(
                summary, step.tool, f"Tool risk level: {tool_cap.risk_level.value}"
            )
            if reviewed is None:
                self._log_safety(step.tool, summary, "risk_rejected",
                                 f"Rejected {tool_cap.risk_level.value} tool")
                raise PermissionDeniedError(
                    f"High-risk tool {step.tool} (risk={tool_cap.risk_level.value}) rejected"
                )
            self._log_safety(step.tool, summary, "risk_accepted",
                             f"Approved {tool_cap.risk_level.value} tool")

    def _log_safety(
        self, tool: str, command: str, action: str, reason: str = ""
    ) -> None:
        logger.info("Permission: tool=%s action=%s reason=%s", tool, action, reason)
        try:
            from .session_log import session_logger as _sl
            _sl.add_safety_event("executor", command, f"{action}:{reason}")
        except Exception:
            pass

    def reset(self) -> None:
        self._budget = ExecutionBudget()
        self._tracker.reset()

    async def close(self, timeout: float | None = None) -> None:
        await self._pool.close(timeout=timeout)

    def stats(self) -> dict[str, Any]:
        return {
            "budget": {
                "iterations": self._budget._iterations,
                "tool_calls": self._budget._tool_calls,
                "elapsed_s": round(self._budget.elapsed, 1),
            },
            "tracker": {
                "failures": dict(self._tracker._failure_counts),
                "no_progress": self._tracker._no_progress_count,
            },
        }
