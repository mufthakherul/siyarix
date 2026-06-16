# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registry executor — executes plan steps via ToolRegistry with guardrails and DAG support."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .events import Event, EventType
from .exceptions import PermissionDeniedError, ToolExecutionError, ToolNotFoundError
from .executor import BaseExecutor, StepExecutor
from .models import ExecutionPlan, PlanStep, PlanStatus, StepStatus
from .planner_registry import TOOL_ALTERNATIVES
from .registry import ToolRegistry

logger = logging.getLogger(__name__)


class RegistryExecutor(BaseExecutor):
    """Executes plan steps through the ToolRegistry with full guardrails, DAG workflows, and alternative fallback.

    Features
    --------
    - Tool registry dispatch with capability lookup
    - DAG workflow engine support for complex dependencies
    - Automatic alternative tool fallback on failure
    - Tool auto-install for missing executables
    - Permission gate for high-risk operations
    - DLP redaction of sensitive values
    - Budget and guardrail enforcement
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        max_workers: int = 10,
        permission_gate: Any = None,
    ) -> None:
        super().__init__(max_workers=max_workers, permission_gate=permission_gate)
        self._registry = registry
        self._custom_executors: dict[str, StepExecutor] = {}

    @property
    def registry(self) -> ToolRegistry | None:
        return self._registry

    def register_executor(self, tool: str, executor: StepExecutor) -> None:
        self._custom_executors[tool] = executor

    async def execute_plan(
        self, plan: ExecutionPlan, executor_fn: StepExecutor | None = None
    ) -> ExecutionPlan:
        self._budget.reset_timer()
        plan.status = PlanStatus.ACTIVE

        await self._event_bus.emit(
            Event(
                type=EventType.PLAN_CREATED,
                source="executor_registry",
                data={"plan_id": plan.id, "goal": plan.goal, "steps": len(plan.steps)},
            )
        )
        total_steps = len(plan.steps)

        while not plan.is_complete:
            if self._budget.is_exhausted:
                break
            ready_steps = plan.get_ready_steps()
            if not ready_steps:
                if plan.pending_steps:
                    blocked = True
                    for step in plan.pending_steps:
                        step_blocked = False
                        for dep_id in step.dependencies:
                            dep_step = plan.get_step(dep_id)
                            if dep_step is None or dep_step.status == StepStatus.FAILED:
                                step_blocked = True
                                break
                        if not step_blocked:
                            blocked = False
                            break
                    if blocked:
                        logger.warning("Plan %s is deadlocked; breaking", plan.id)
                        break
                    await asyncio.sleep(0.01)
                    continue
                break

            can_parallel = plan.plan_type.value in ("parallel", "dag") or (
                plan.plan_type.value == "sequential"
                and len(ready_steps) > 1
                and all(not s.dependencies for s in ready_steps)
            )
            if can_parallel:
                tasks = [self._pool.submit(self._execute_step, s, executor_fn) for s in ready_steps]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, res in enumerate(results):
                    if isinstance(res, BaseException):
                        logger.error(
                            "Parallel step %s exception: %s", ready_steps[i].id, res, exc_info=res
                        )
            else:
                for s in ready_steps:
                    await self._execute_step(s, executor_fn)
                    if self._budget.is_exhausted:
                        break

            completed = sum(1 for s in plan.steps if s.is_terminal)
            pct = (completed / total_steps * 100.0) if total_steps else 100.0
            logger.debug("Plan %s progress: %.1f%% (%d/%d)", plan.id, pct, completed, total_steps)

        plan.status = PlanStatus.COMPLETED if not plan.has_failures else PlanStatus.FAILED
        await self._event_bus.emit(
            Event(
                type=EventType.PLAN_COMPLETE,
                source="executor_registry",
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
                source="executor_registry",
                data={"step_id": step.id, "tool": step.tool},
            )
        )
        if self._on_step_progress:
            self._on_step_progress(step)
        start = __import__("time").monotonic()
        try:
            result = await asyncio.wait_for(
                self._try_execute(step, executor_fn),
                timeout=step.timeout,
            )
            step.duration_ms = (__import__("time").monotonic() - start) * 1000
            step.result = result
            if result.get("status") == "error":
                step.status = StepStatus.FAILED
                self._tracker.record(step.tool, str(sorted(step.args.items())), False)
                await self._event_bus.emit(
                    Event(
                        type=EventType.PLAN_STEP_FAILED,
                        source="executor_registry",
                        data={"step_id": step.id, "error": result.get("error", "")},
                    )
                )
            else:
                step.status = StepStatus.COMPLETED
                self._tracker.record(step.tool, str(sorted(step.args.items())), True)
                await self._event_bus.emit(
                    Event(
                        type=EventType.PLAN_STEP_COMPLETE,
                        source="executor_registry",
                        data={"step_id": step.id, "duration_ms": step.duration_ms},
                    )
                )
        except asyncio.TimeoutError:
            step.duration_ms = (__import__("time").monotonic() - start) * 1000
            step.status = StepStatus.FAILED
            step.result = {"status": "error", "error": f"Step timed out after {step.timeout}s"}
            self._tracker.record(step.tool, str(sorted(step.args.items())), False)
            logger.warning("Step %s timed out after %.1fs", step.id, step.timeout)
        except asyncio.CancelledError:
            step.status = StepStatus.SKIPPED
            raise
        except Exception as e:
            step.duration_ms = (__import__("time").monotonic() - start) * 1000
            step.status = StepStatus.FAILED
            step.result = {"status": "error", "error": str(e)}
            self._tracker.record(step.tool, str(sorted(step.args.items())), False)
        if self._on_step_progress:
            self._on_step_progress(step)

    async def _try_execute(
        self, step: PlanStep, executor_fn: StepExecutor | None
    ) -> dict[str, Any]:
        if executor_fn:
            return await executor_fn(step)
        if step.tool in self._custom_executors:
            return await self._custom_executors[step.tool](step)
        if not self._registry or not step.tool:
            return {"status": "error", "error": f"No executor for: {step.tool}"}

        if self._permission_gate:
            await self._check_permissions(step)
        if not self._budget.consume_tool_call():
            return {"status": "error", "error": "Tool call budget exhausted"}

        args_key = str(sorted(step.args.items()))
        guardrail = self._tracker.record(step.tool, args_key, False)
        if guardrail and "BLOCKED" in guardrail:
            return {"status": "error", "error": guardrail}

        try:
            result = await self._registry.execute(step.tool, **step.args)
        except ToolNotFoundError:
            result = {"status": "error", "error": str(ToolNotFoundError), "tool": step.tool}
        except ToolExecutionError as e:
            result = {"status": "error", "error": str(e), "tool": step.tool}
        except PermissionDeniedError:
            raise
        result = await self._apply_dlp(result)
        if result.get("status") == "error":
            result = await self._handle_tool_error(step, result)
        if result.get("status") == "error":
            result = await self._try_alternatives(step, result)
        return result

    async def _handle_tool_error(self, step: PlanStep, result: dict[str, Any]) -> dict[str, Any]:
        err_msg = str(result.get("error", "")).lower()
        if any(x in err_msg for x in ["not found", "not recognized", "executable", "no such"]):
            try:
                import sys as _sys

                if _sys.stdout and _sys.stdout.isatty():
                    from rich.prompt import Confirm
                    from .tool_installer import ToolInstaller

                    want = Confirm.ask(
                        f"\n[yellow]Tool [cyan]{step.tool}[/cyan] is missing. Auto-install it?[/yellow]",
                        default=True,
                    )
                    if want:
                        installer = ToolInstaller()
                        if installer.install_tool(step.tool):
                            from .tool_models import invalidate_which_cache

                            invalidate_which_cache()
                            try:
                                result = await self._registry.execute(step.tool, **step.args)
                            except (ToolNotFoundError, ToolExecutionError) as e:
                                result = {"status": "error", "error": str(e), "tool": step.tool}
                            result = await self._apply_dlp(result)
            except Exception as exc:
                logger.warning("Tool auto-install failed for %s: %s", step.tool, exc)
        return result

    async def _try_alternatives(self, step: PlanStep, result: dict[str, Any]) -> dict[str, Any]:
        alt_tools = TOOL_ALTERNATIVES.get(step.tool, [])
        for alt in alt_tools:
            if alt not in self._custom_executors and not (
                self._registry and self._registry.graph.get_tool(alt)
            ):
                continue
            alt_args_key = str(sorted(step.args.items()))
            guardrail = self._tracker.record(alt, alt_args_key, False)
            if guardrail and "BLOCKED" in guardrail:
                continue
            try:
                alt_result = await self._registry.execute(alt, **step.args)
            except (ToolNotFoundError, ToolExecutionError) as e:
                alt_result = {"status": "error", "error": str(e), "tool": alt}
            if alt_result.get("status") != "error":
                step.tool = alt
                return alt_result
            self._tracker.record(alt, alt_args_key, False)
        return result

    async def execute_workflow(self, plan: ExecutionPlan) -> ExecutionPlan:
        """Execute a DAG workflow using the WorkflowEngine."""
        if not hasattr(plan, "plan_type") or getattr(plan.plan_type, "value", None) != "dag":
            return await self.execute_plan(plan)
        try:
            from .workflow import WorkflowEngine, WorkflowStatus

            engine = WorkflowEngine()
            nodes = [
                {
                    "id": s.id,
                    "name": s.tool or s.description,
                    "step_fn": s.tool,
                    "args": s.args,
                    "timeout": s.timeout,
                }
                for s in plan.steps
            ]
            edges = [{"source": dep, "target": s.id} for s in plan.steps for dep in s.dependencies]
            workflow = engine.create_workflow(
                name=plan.goal, description=plan.goal, nodes=nodes, edges=edges
            )
            wf_result = await engine.run_workflow(workflow)
            plan.status = (
                PlanStatus.COMPLETED
                if wf_result.status == WorkflowStatus.COMPLETED
                else PlanStatus.FAILED
            )
        except Exception as exc:
            logger.warning("Workflow engine failed, falling back to sequential: %s", exc)
            plan = await self.execute_plan(plan)
        return plan


__all__ = [
    "RegistryExecutor",
]
