# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registry executor — executes plan steps via ToolRegistry with guardrails and DAG support."""

from __future__ import annotations

import asyncio
import logging
import time
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

            plan_type_val = (
                plan.plan_type.value
                if hasattr(plan.plan_type, "value")
                else str(plan.plan_type or "")
            )
            can_parallel = plan_type_val in ("parallel", "dag") or (
                plan_type_val == "sequential"
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
                        break  # type: ignore[unreachable]

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
            res = self._on_step_progress(step)
            if hasattr(res, "__await__"):
                await res  # type: ignore[misc]
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                self._try_execute(step, executor_fn),
                timeout=step.timeout,
            )
            step.duration_ms = (time.monotonic() - start) * 1000
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
            step.duration_ms = (time.monotonic() - start) * 1000
            step.status = StepStatus.FAILED
            step.result = {"status": "error", "error": f"Step timed out after {step.timeout}s"}
            self._tracker.record(step.tool, str(sorted(step.args.items())), False)
            logger.warning("Step %s timed out after %.1fs", step.id, step.timeout)
        except asyncio.CancelledError:
            step.status = StepStatus.SKIPPED
            raise
        except Exception as e:
            step.duration_ms = (time.monotonic() - start) * 1000
            step.status = StepStatus.FAILED
            step.result = {"status": "error", "error": str(e)}
            self._tracker.record(step.tool, str(sorted(step.args.items())), False)
        if self._on_step_progress:
            res = self._on_step_progress(step)
            if hasattr(res, "__await__"):
                await res  # type: ignore[misc]

    async def _try_execute(
        self, step: PlanStep, executor_fn: StepExecutor | None
    ) -> dict[str, Any]:
        if executor_fn:
            return await executor_fn(step)
        if step.tool in self._custom_executors:
            return await self._custom_executors[step.tool](step)
        if not self._registry or not step.tool:
            return {"status": "error", "error": f"No executor for: {step.tool}"}

        # Guardrail checks
        if step.tool:
            fail_count = self._tracker._failure_counts.get(step.tool, 0)
            if fail_count >= self._tracker._config.exact_failure_block_after:
                return {
                    "status": "error",
                    "error": f"BLOCKED: {step.tool} failed {fail_count} times",
                    "tool": step.tool,
                }
            consecutive = self._tracker._consecutive_same.get(step.tool, 0)
            if consecutive >= self._tracker._config.same_tool_failure_halt_after:
                return {
                    "status": "error",
                    "error": f"HALTED: {step.tool} called {consecutive} times consecutively",
                    "tool": step.tool,
                }
            if self._tracker._no_progress_count >= self._tracker._config.no_progress_block_after:
                return {
                    "status": "error",
                    "error": f"BLOCKED: No progress for {self._tracker._no_progress_count} calls",
                    "tool": step.tool,
                }

        if self._permission_gate:
            await self._check_permissions(step)
        if not self._budget.consume_tool_call():
            return {"status": "error", "error": "Tool call budget exhausted"}

        args_key = str(sorted(step.args.items()))

        try:
            result = await self._registry.execute(step.tool, **step.args)
        except ToolNotFoundError as e:
            self._tracker.record(step.tool, args_key, False)
            result = {"status": "error", "error": str(e), "tool": step.tool}
        except ToolExecutionError as e:
            self._tracker.record(step.tool, args_key, False)
            result = {"status": "error", "error": str(e), "tool": step.tool}
        except PermissionDeniedError:
            raise
        else:
            self._tracker.record(step.tool, args_key, result.get("status") != "error")
        result = await self._apply_dlp(result)
        if result.get("status") == "error":
            result = await self._handle_tool_error(step, result)
        if result.get("status") == "error":
            result = await self._try_alternatives(step, result)
        return result

    async def _handle_tool_error(self, step: PlanStep, result: dict[str, Any]) -> dict[str, Any]:
        err_msg = str(result.get("error", "")).lower()

        # 1. Self-Correction Heuristic: Stripping unrecognized arguments
        if "unrecognized option" in err_msg or "invalid option" in err_msg:
            # Try to extract the bad flag from the error message using regex
            import re

            match = re.search(
                r"(?:unrecognized option|invalid option)\s+['\"]?(-{1,2}[\w-]+)['\"]?", err_msg
            )
            bad_flag = match.group(1) if match else None

            if bad_flag and "flags" in step.args:
                logger.info(f"Self-correcting tool {step.tool}: stripping bad flag {bad_flag}")
                new_flags = step.args["flags"].replace(bad_flag, "").strip()
                # Clean up double spaces
                new_flags = " ".join(new_flags.split())
                step.args["flags"] = new_flags

                try:
                    assert self._registry is not None
                    retry_result = await self._registry.execute(step.tool, **step.args)
                    retry_result = await self._apply_dlp(retry_result)
                    if retry_result.get("status") != "error":
                        return retry_result
                except Exception:
                    pass

        # 2. Missing Tool Installation Heuristic
        if any(
            x in err_msg
            for x in [
                "not found",
                "not installed",
                "unavailable",
                "not recognized",
                "executable",
                "no such",
            ]
        ):
            try:
                import sys as _sys

                if _sys.stdout and _sys.stdout.isatty():
                    from .tool_installer import ToolInstaller, tty_confirm
                    from .subprocess_utils import _format_not_found

                    # Show a clear pre-install message with install hint
                    hint = _format_not_found([step.tool])
                    console = __import__("rich").console.Console(stderr=True)
                    console.print(f"\n[yellow]{hint}[/yellow]")

                    want = tty_confirm(
                        f"\n[yellow]Install [cyan]{step.tool}[/cyan] now?[/yellow]",
                        default=True,
                    )
                    if want:
                        installer = ToolInstaller()
                        if installer.install_tool(step.tool):
                            from .tool_models import invalidate_which_cache

                            invalidate_which_cache()
                            if self._registry is None:
                                return {
                                    "status": "error",
                                    "error": "Registry not initialised",
                                    "tool": step.tool,
                                }
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
            if self._registry is None:
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

            # Register a step executor per step so we can report progress
            for s in plan.steps:

                async def _run_step(args: dict[str, Any], _step: PlanStep = s) -> dict[str, Any]:
                    _step.status = StepStatus.RUNNING
                    if self._on_step_progress:
                        res = self._on_step_progress(_step)
                        if hasattr(res, "__await__"):
                            await res  # type: ignore[misc]
                    _result = await self._try_execute(_step, None)
                    _step.result = _result
                    _step.status = (
                        StepStatus.COMPLETED
                        if _result.get("status") != "error"
                        else StepStatus.FAILED
                    )
                    _step.duration_ms = _result.get("duration_ms", 0)
                    if self._on_step_progress:
                        res = self._on_step_progress(_step)
                        if hasattr(res, "__await__"):
                            await res  # type: ignore[misc]
                    return _result

                engine.register_step(s.id, _run_step)

            nodes = [
                {
                    "id": s.id,
                    "name": s.tool or s.description,
                    "step_fn": s.id,
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

            # Map statuses back
            for s in plan.steps:
                wf_node = wf_result.get_node(s.id)
                if wf_node:
                    s.result = wf_node.result

            plan.status = (
                PlanStatus.COMPLETED
                if wf_result.status == WorkflowStatus.COMPLETED
                else PlanStatus.FAILED
            )
        except Exception as exc:
            logger.warning("Workflow engine failed, falling back to sequential: %s", exc)
            plan = await self.execute_plan(plan)
        return plan


Executor = RegistryExecutor

__all__ = [
    "RegistryExecutor",
    "Executor",
]
