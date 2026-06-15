# SPDX-License-Identifier: AGPL-3.0-or-later
"""Execution engine with guardrails, recovery, and tool dispatch."""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import re
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from .events import Event, EventType, get_event_bus
from .audit_log import audit, AuditEventType, AuditSeverity
from .exceptions import PermissionDeniedError
from .permission_gate import PermissionGate
from .planner import TOOL_ALTERNATIVES, ExecutionPlan, PlanStep, StepStatus, PlanStatus
from .registry import RiskLevel, ToolRegistry
from .worker_pool import AsyncWorkerPool

logger = logging.getLogger(__name__)

__all__ = [
    "ExecutionBudget",
    "Executor",
    "GuardrailConfig",
    "StepCallback",
    "StepExecutor",
    "ToolCallTracker",
]

StepExecutor = Callable[[PlanStep], Coroutine[Any, Any, dict[str, Any]]]

# ---------------------------------------------------------------------------
# Sensitive-value redaction for args displayed in summaries (M-26)
# ---------------------------------------------------------------------------
_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "authorization", "credential", "credentials", "private_key",
    "access_key", "secret_key", "session_token", "cookie",
})
_SENSITIVE_RE = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|auth|key|credential)",
    re.IGNORECASE,
)


def _redact_value(key: str, value: Any) -> str:
    """Return a redacted string representation if *key* looks sensitive.

    Keys are matched against a known set and a broad regex fallback.
    Values longer than 4 characters are masked; shorter ones are fully hidden.
    """
    if key.lower() in _SENSITIVE_KEYS or _SENSITIVE_RE.search(key):
        raw = str(value)
        if len(raw) > 4:
            return raw[:2] + "***" + raw[-2:]
        return "***"
    return str(value)


# ---------------------------------------------------------------------------
# Cached module-level lazy import for shell_review (L-28)
# ---------------------------------------------------------------------------
@functools.lru_cache(maxsize=1)
def _get_review_and_confirm() -> Callable[..., str | None]:
    """Lazily import and cache ``review_and_confirm`` from :mod:`.shell_review`.

    This avoids an import inside every async call while still deferring the
    import until it is actually needed (breaking a potential circular import).
    """
    from .shell_review import review_and_confirm
    return review_and_confirm


@functools.lru_cache(maxsize=1)
def _get_session_logger() -> Any:
    """Lazily import and cache ``session_logger``."""
    from .session_log import session_logger
    return session_logger


@functools.lru_cache(maxsize=1)
def _get_dlp_engine() -> Any:
    """Lazily import and cache ``DLPEngine``."""
    try:
        from .dlp import DLPEngine
        return DLPEngine(redact_secrets=True, redact_pii=True)
    except ImportError:
        logger.debug("DLPEngine not available, skipping redaction")
        return None


@dataclass
class ExecutionBudget:
    """Tracks and enforces resource consumption limits for a plan execution.

    Limits cover iteration count, total tool calls, and wall-clock duration.
    """

    max_iterations: int = 50
    max_tool_calls: int = 100
    max_duration_s: float = 600.0
    _iterations: int = field(default=0, repr=False)
    _tool_calls: int = field(default=0, repr=False)
    _start_time: float = field(default_factory=time.monotonic, repr=False)

    # -- public properties (M-09) -------------------------------------------

    @property
    def iterations(self) -> int:
        """Number of iterations consumed so far."""
        return self._iterations

    @property
    def tool_calls(self) -> int:
        """Number of tool calls consumed so far."""
        return self._tool_calls

    @property
    def remaining_iterations(self) -> int:
        """Iterations remaining before the budget is exhausted."""
        return max(0, self.max_iterations - self._iterations)

    @property
    def remaining_tool_calls(self) -> int:
        """Tool calls remaining before the budget is exhausted."""
        return max(0, self.max_tool_calls - self._tool_calls)

    @property
    def elapsed(self) -> float:
        """Seconds elapsed since the timer was (re)started."""
        return time.monotonic() - self._start_time

    @property
    def is_exhausted(self) -> bool:
        """``True`` when any limit has been reached."""
        return (
            self._iterations >= self.max_iterations
            or self._tool_calls >= self.max_tool_calls
            or self.elapsed >= self.max_duration_s
        )

    @property
    def progress_pct(self) -> float:
        """Rough progress percentage based on iteration consumption."""
        if not self.max_iterations:
            return 100.0
        return min(100.0, (self._iterations / self.max_iterations) * 100.0)

    # -- mutators -----------------------------------------------------------

    def consume_iteration(self) -> bool:
        """Consume one iteration.  Returns ``False`` if already exhausted."""
        if self.is_exhausted:
            return False
        self._iterations += 1
        return True

    def consume_tool_call(self) -> bool:
        """Consume one tool call.  Returns ``False`` if already exhausted."""
        if self.is_exhausted:
            return False
        self._tool_calls += 1
        return True

    def reset_timer(self) -> None:
        """Reset the start time to *now* (monotonic clock).

        Call this at the beginning of ``execute_plan`` so that budget duration
        measures actual execution time, not object-creation time.  (H-18)
        """
        self._start_time = time.monotonic()

    def reset(self) -> None:
        """Fully reset all consumed counters **and** the timer."""
        self._iterations = 0
        self._tool_calls = 0
        self.reset_timer()


@dataclass
class GuardrailConfig:
    """Thresholds that govern automatic tool-call blocking."""

    exact_failure_warn_after: int = 2
    exact_failure_block_after: int = 5
    same_tool_failure_halt_after: int = 8
    no_progress_block_after: int = 5


class ToolCallTracker:
    """Records tool-call outcomes and enforces guardrail policies."""

    def __init__(self, config: GuardrailConfig | None = None) -> None:
        from .config import get_config_dir
        self._config = config or GuardrailConfig()
        self._failure_counts: dict[str, int] = {}
        self._consecutive_same: dict[str, int] = {}
        self._no_progress_count = 0
        self._last_mutation = ""
        self._state_file = get_config_dir() / "tool_failures.json"
        self._load_state()

    def _load_state(self) -> None:
        if self._state_file.exists():
            try:
                data = json.loads(self._state_file.read_text())
                self._failure_counts = data.get("failure_counts", {})
                self._consecutive_same = data.get("consecutive_same", {})
                self._no_progress_count = data.get("no_progress_count", 0)
                self._last_mutation = data.get("last_mutation", "")
            except Exception as exc:
                logger.debug("Failed to load tool failure state: %s", exc)

    def _save_state(self) -> None:
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            self._state_file.write_text(json.dumps({
                "failure_counts": self._failure_counts,
                "consecutive_same": self._consecutive_same,
                "no_progress_count": self._no_progress_count,
                "last_mutation": self._last_mutation
            }))
        except Exception as exc:
            logger.debug("Failed to save tool failure state: %s", exc)

    # -- public properties (M-09) -------------------------------------------

    @property
    def failure_counts(self) -> dict[str, int]:
        """Per-tool failure counts (read-only copy)."""
        return dict(self._failure_counts)

    @property
    def no_progress_count(self) -> int:
        """Number of consecutive calls with no forward progress."""
        return self._no_progress_count

    # -- recording ----------------------------------------------------------

    def record(self, tool: str, args_key: str, success: bool) -> str | None:
        """Record a tool invocation outcome and return a guardrail message (or ``None``).

        Parameters
        ----------
        tool:
            Name of the tool that was invoked.
        args_key:
            A deterministic string key derived from the call arguments.
        success:
            Whether the invocation succeeded.

        Returns
        -------
        str | None
            A ``"BLOCKED: …"`` / ``"HALTED: …"`` message if a guardrail
            threshold has been reached, otherwise ``None``.
        """
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
            self._save_state()
            return f"BLOCKED: {tool} failed {self._failure_counts[tool]} times"
        if self._consecutive_same.get(tool, 0) >= self._config.same_tool_failure_halt_after:
            self._save_state()
            return f"HALTED: {tool} called {self._consecutive_same[tool]} times consecutively"
        if self._no_progress_count >= self._config.no_progress_block_after:
            self._save_state()
            return f"BLOCKED: No progress for {self._no_progress_count} calls"
        self._save_state()
        return None

    def reset(self) -> None:
        """Clear all recorded state."""
        self._failure_counts.clear()
        self._consecutive_same.clear()
        self._no_progress_count = 0
        self._save_state()


StepCallback = Callable[[PlanStep], None]


class Executor:
    """Drives plan execution with budgets, guardrails, parallelism, and recovery."""

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
        """Register (or clear) a synchronous callback invoked on step state changes."""
        self._on_step_progress = cb

    @property
    def budget(self) -> ExecutionBudget:
        """The current :class:`ExecutionBudget` instance."""
        return self._budget

    def register_executor(self, tool: str, executor: StepExecutor) -> None:
        """Register a custom async step executor for *tool*."""
        self._custom_executors[tool] = executor

    # ------------------------------------------------------------------
    # Plan-level execution
    # ------------------------------------------------------------------

    async def execute_plan(
        self, plan: ExecutionPlan, executor_fn: StepExecutor | None = None
    ) -> ExecutionPlan:
        """Execute all steps in *plan*, respecting dependencies, budgets and guardrails.

        Returns the mutated *plan* with updated step statuses and results.
        """
        # H-18: reset timer so duration measures actual execution, not
        # the time between ExecutionBudget construction and now.
        self._budget.reset_timer()

        plan.status = PlanStatus.ACTIVE
        await self._event_bus.emit(
            Event(
                type=EventType.PLAN_CREATED,
                source="executor",
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
                    # M-23: Detect if the plan is permanently blocked (deadlocked).
                    # A plan is blocked if every pending step depends on at least one
                    # step that has failed or is missing from the plan entirely. (H-20)
                    blocked = True
                    for step in plan.pending_steps:
                        step_permanently_blocked = False
                        for dep_id in step.dependencies:
                            dep_step = plan.get_step(dep_id)
                            if dep_step is None or dep_step.status == StepStatus.FAILED:
                                step_permanently_blocked = True
                                break
                        if not step_permanently_blocked:
                            # This step might still become ready if its dependencies complete.
                            blocked = False
                            break

                    if blocked:
                        logger.warning("Plan %s is deadlocked; breaking execution loop.", plan.id)
                        break

                    await asyncio.sleep(0.01)  # Brief yield to prevent busy-wait
                    continue
                else:
                    break
            # Auto-parallel: run independent steps concurrently
            can_parallel = plan.plan_type.value in ("parallel", "dag") or (
                plan.plan_type.value == "sequential"
                and len(ready_steps) > 1
                and all(not s.dependencies for s in ready_steps)
            )
            if can_parallel:
                tasks = []
                for s in ready_steps:
                    tasks.append(self._pool.submit(self._execute_step, s, executor_fn))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                # M-41: log exceptions that gather swallowed
                for i, res in enumerate(results):
                    if isinstance(res, BaseException):
                        logger.error(
                            "Parallel step %s raised an exception: %s",
                            ready_steps[i].id,
                            res,
                            exc_info=res,
                        )
            else:
                for s in ready_steps:
                    await self._execute_step(s, executor_fn)
                    if self._budget.is_exhausted:
                        break

            # Progress percentage tracking
            completed = sum(1 for s in plan.steps if s.is_terminal)
            pct = (completed / total_steps * 100.0) if total_steps else 100.0
            logger.debug("Plan %s progress: %.1f%% (%d/%d steps)", plan.id, pct, completed, total_steps)

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

    # ------------------------------------------------------------------
    # Step-level execution
    # ------------------------------------------------------------------

    async def _execute_step(self, step: PlanStep, executor_fn: StepExecutor | None) -> None:
        """Execute a single plan step with budget, guardrail and timeout enforcement."""
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
        start = time.monotonic()
        try:
            # Per-step timeout: honour PlanStep.timeout (defaults to 300 s)
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
                        source="executor",
                        data={"step_id": step.id, "error": result.get("error", "")},
                    )
                )
            else:
                step.status = StepStatus.COMPLETED
                # H-19 / M-25: record success AFTER execution succeeds
                self._tracker.record(step.tool, str(sorted(step.args.items())), True)
                await self._event_bus.emit(
                    Event(
                        type=EventType.PLAN_STEP_COMPLETE,
                        source="executor",
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
            self._on_step_progress(step)

    async def _try_execute(
        self, step: PlanStep, executor_fn: StepExecutor | None
    ) -> dict[str, Any]:
        """Attempt tool execution with automatic fallback to alternatives on failure."""
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

            # H-19 / M-25: guardrail check BEFORE execution uses success=False
            # as a pessimistic pre-check; real success is recorded in
            # _execute_step after the call returns.
            args_key = str(sorted(step.args.items()))
            guardrail = self._tracker.record(step.tool, args_key, False)
            if guardrail and "BLOCKED" in guardrail:
                return {"status": "error", "error": guardrail}

            result = await self._registry.execute(step.tool, **step.args)

            dlp = _get_dlp_engine()
            if dlp is not None:
                result = dlp.redact_dict(result)
            if result.get("status") == "error":
                err_msg = str(result.get("error", "")).lower()
                if any(x in err_msg for x in ["not found", "not recognized", "executable"]):
                    if sys.stdout and sys.stdout.isatty():
                        try:
                            from rich.prompt import Confirm
                            from siyarix.tool_installer import ToolInstaller
                            want = Confirm.ask(f"\n[yellow]Tool [cyan]{step.tool}[/cyan] is missing. Auto-install it?[/yellow]", default=True)
                            if want:
                                installer = ToolInstaller()
                                if installer.install_tool(step.tool):
                                    result = await self._registry.execute(step.tool, **step.args)
                                    if dlp is not None:
                                        result = dlp.redact_dict(result)
                        except Exception as exc:
                            logger.warning("Tool auto-install failed for %s: %s", step.tool, exc)

            if result.get("status") == "error":
                alt_tools = TOOL_ALTERNATIVES.get(step.tool, [])
                for alt in alt_tools:
                    if alt in self._custom_executors or (
                        self._registry and self._registry.graph.get_tool(alt)
                    ):
                        alt_args_key = str(sorted(step.args.items()))
                        guardrail = self._tracker.record(alt, alt_args_key, False)
                        if guardrail and "BLOCKED" in guardrail:
                            continue
                        alt_result = await self._registry.execute(alt, **step.args)
                        if alt_result.get("status") != "error":
                            step.tool = alt
                            # Success recorded by _execute_step
                            return alt_result
                        # Record alt failure
                        self._tracker.record(alt, alt_args_key, False)
            return result
        return {"status": "error", "error": f"No executor for: {step.tool}"}

    async def _check_permissions(self, step: PlanStep) -> None:
        """Verify permission gate and optionally prompt the user for review."""
        if not self._permission_gate:
            return
        command = step.command or step.args.get("command", "")
        tool_cap = self._registry.graph.get_tool(step.tool) if self._registry else None

        review_and_confirm = _get_review_and_confirm()

        if command:
            gate_result = self._permission_gate.check(command, tool=step.tool)
            if not gate_result.allowed:
                self._log_safety(step.tool, command, "blocked", gate_result.reason)
                raise PermissionDeniedError(gate_result.reason)
            if gate_result.requires_review:
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
            # M-26: redact sensitive argument values
            summary = f"{step.tool} {' '.join(_redact_value(k, v) for k, v in step.args.items())}"
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
        """Persist a safety/permission event to the session log."""
        logger.info("Permission: tool=%s action=%s reason=%s", tool, action, reason)
        try:
            _sl = _get_session_logger()
            _sl.add_safety_event("executor", command, f"{action}:{reason}")

            # SAFE-03: Audit trail entry for manual approvals
            if action in ("approved", "risk_accepted"):
                audit(
                    AuditEventType.SECURITY_APPROVAL,
                    AuditSeverity.HIGH,
                    "Manual execution approval granted",
                    {"tool": tool, "command": command, "reason": reason}
                )
            elif action in ("cancelled", "risk_rejected", "blocked"):
                audit(
                    AuditEventType.SECURITY_DENIAL,
                    AuditSeverity.MEDIUM,
                    "Execution denied",
                    {"tool": tool, "command": command, "reason": reason, "action": action}
                )
        except Exception:
            # L-27: log at debug instead of silently swallowing
            logger.debug(
                "Failed to record safety event for tool=%s action=%s",
                tool, action, exc_info=True,
            )

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset budget and tracker to a clean state."""
        self._budget = ExecutionBudget()
        self._tracker.reset()

    async def close(self, timeout: float | None = None) -> None:
        """Shut down the worker pool, optionally waiting up to *timeout* seconds."""
        await self._pool.close(timeout=timeout)

    def stats(self) -> dict[str, Any]:
        """Return a snapshot of budget consumption and tracker state.

        Uses public properties rather than reaching into private fields (M-09).
        """
        return {
            "budget": {
                "iterations": self._budget.iterations,
                "tool_calls": self._budget.tool_calls,
                "elapsed_s": round(self._budget.elapsed, 1),
                "progress_pct": round(self._budget.progress_pct, 1),
            },
            "tracker": {
                "failures": self._tracker.failure_counts,
                "no_progress": self._tracker.no_progress_count,
            },
        }
