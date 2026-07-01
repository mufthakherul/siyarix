# SPDX-License-Identifier: AGPL-3.0-or-later
"""Base executor — shared guardrails, budget tracking, DLP, and permission gate for all executor variants."""

from __future__ import annotations

import functools
import json
import logging
import re
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from .events import get_event_bus
from .audit_log import log_event, AuditEventType, AuditSeverity
from .exceptions import PermissionDeniedError
from .permission_gate import PermissionGate
from .models import ExecutionPlan, PlanStep
from .worker_pool import AsyncWorkerPool

logger = logging.getLogger(__name__)

__all__ = [
    "ExecutionBudget",
    "BaseExecutor",
    "GuardrailConfig",
    "StepCallback",
    "StepExecutor",
    "ToolCallTracker",
]

StepExecutor = Callable[[PlanStep], Coroutine[Any, Any, dict[str, Any]]]

# ---------------------------------------------------------------------------
# Sensitive-value redaction
# ---------------------------------------------------------------------------
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "private_key",
        "access_key",
        "secret_key",
        "session_token",
        "cookie",
    }
)
_SENSITIVE_RE = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|auth|key|credential)",
    re.IGNORECASE,
)


def _redact_value(key: str, value: Any) -> str:
    if key.lower() in _SENSITIVE_KEYS or _SENSITIVE_RE.search(key):
        raw = str(value)
        if len(raw) > 4:
            return raw[:2] + "***" + raw[-2:]
        return "***"
    return str(value)


# ---------------------------------------------------------------------------
# Lazy imports (cached)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _get_review_and_confirm() -> Callable[..., str | None]:
    from .shell_review import review_and_confirm

    return review_and_confirm


@functools.lru_cache(maxsize=1)
def _get_session_logger() -> Any:
    from .session_log import session_logger

    return session_logger


_DLP_ENGINE: Any = None


def _get_dlp_engine() -> Any:
    global _DLP_ENGINE
    if _DLP_ENGINE is None:
        try:
            from .dlp import DLPEngine

            _DLP_ENGINE = DLPEngine(redact_secrets=True, redact_pii=True)
        except ImportError:
            logger.debug("DLPEngine not available, skipping redaction")
            _DLP_ENGINE = False
    return _DLP_ENGINE if _DLP_ENGINE is not False else None


# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------


@dataclass
class ExecutionBudget:
    """Tracks and enforces resource consumption limits for plan execution."""

    max_iterations: int = 50
    max_tool_calls: int = 100
    max_duration_s: float = 600.0
    _iterations: int = field(default=0, repr=False)
    _tool_calls: int = field(default=0, repr=False)
    _start_time: float = field(default_factory=time.monotonic, repr=False)

    @property
    def iterations(self) -> int:
        return self._iterations

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    @property
    def remaining_iterations(self) -> int:
        return max(0, self.max_iterations - self._iterations)

    @property
    def remaining_tool_calls(self) -> int:
        return max(0, self.max_tool_calls - self._tool_calls)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def is_exhausted(self) -> bool:
        return (
            self._iterations >= self.max_iterations
            or self._tool_calls >= self.max_tool_calls
            or self.elapsed >= self.max_duration_s
        )

    @property
    def progress_pct(self) -> float:
        if not self.max_iterations:
            return 100.0
        return min(100.0, (self._iterations / self.max_iterations) * 100.0)

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

    def reset_timer(self) -> None:
        self._start_time = time.monotonic()

    def reset(self) -> None:
        self._iterations = 0
        self._tool_calls = 0
        self.reset_timer()


@dataclass
class GuardrailConfig:
    """Thresholds for automatic tool-call blocking."""

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
        self._dirty = False
        self._debounce_counter = 0
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

    def _save_state(self, force: bool = False) -> None:
        self._debounce_counter += 1
        if not force and self._debounce_counter % 10 != 0:
            self._dirty = True
            return
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            self._state_file.write_text(
                json.dumps(
                    {
                        "failure_counts": self._failure_counts,
                        "consecutive_same": self._consecutive_same,
                        "no_progress_count": self._no_progress_count,
                        "last_mutation": self._last_mutation,
                    }
                )
            )
            self._dirty = False
        except Exception as exc:
            logger.warning("Failed to save tool failure state: %s", exc)

    @property
    def failure_counts(self) -> dict[str, int]:
        return dict(self._failure_counts)

    @property
    def no_progress_count(self) -> int:
        return self._no_progress_count

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
        self._failure_counts.clear()
        self._consecutive_same.clear()
        self._no_progress_count = 0
        self._save_state()


StepCallback = Callable[[PlanStep], None]


class BaseExecutor:
    """Abstract base executor with shared budget, guardrails, DLP, and permission gate.

    Subclasses implement ``execute_plan()`` and step execution logic.
    """

    def __init__(
        self,
        max_workers: int = 10,
        permission_gate: PermissionGate | None = None,
    ) -> None:
        self._budget = ExecutionBudget()
        self._tracker = ToolCallTracker()
        self._event_bus = get_event_bus()
        self._pool = AsyncWorkerPool(max_workers=max_workers)
        self._on_step_progress: StepCallback | None = None
        self._permission_gate = permission_gate

    def set_progress_callback(self, cb: StepCallback | None) -> None:
        self._on_step_progress = cb

    @property
    def budget(self) -> ExecutionBudget:
        return self._budget

    @property
    def tracker(self) -> ToolCallTracker:
        return self._tracker

    @property
    def pool(self) -> AsyncWorkerPool:
        return self._pool

    async def _apply_dlp(self, result: dict[str, Any]) -> dict[str, Any]:
        dlp = _get_dlp_engine()
        if dlp is not None and isinstance(result, dict):
            return dlp.redact_dict(result)  # type: ignore[no-any-return]
        return result

    async def _check_permissions(self, step: PlanStep) -> None:
        if not self._permission_gate:
            return
        command = step.command or step.args.get("command", "")
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

    def _log_safety(self, tool: str, command: str, action: str, reason: str = "") -> None:
        logger.info("Permission: tool=%s action=%s reason=%s", tool, action, reason)
        try:
            _sl = _get_session_logger()
            _sl.add_safety_event("executor", command, f"{action}:{reason}")
            if action in ("approved", "risk_accepted"):
                log_event(
                    event_type=AuditEventType.SECURITY_APPROVAL,
                    severity=AuditSeverity.HIGH,
                    user="executor",
                    action="Manual execution approval granted",
                    result="granted",
                    details={"tool": tool, "command": command, "reason": reason},
                )
            elif action in ("cancelled", "risk_rejected", "blocked"):
                log_event(
                    event_type=AuditEventType.SECURITY_DENIAL,
                    severity=AuditSeverity.MEDIUM,
                    user="executor",
                    action="Execution denied",
                    result="denied",
                    details={"tool": tool, "command": command, "reason": reason, "action": action},
                )
        except Exception:
            logger.debug(
                "Failed to record safety event for tool=%s action=%s", tool, action, exc_info=True
            )

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def reset(self) -> None:
        self._budget = ExecutionBudget()
        self._tracker.reset()

    async def close(self, timeout: float | None = None) -> None:
        await self._pool.close(timeout=timeout)

    def stats(self) -> dict[str, Any]:
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

    # ── To be implemented by subclasses ───────────────────────────────────

    async def execute_plan(
        self,
        plan: ExecutionPlan,
        executor_fn: StepExecutor | None = None,
        live_display: bool = True,
    ) -> ExecutionPlan:
        raise NotImplementedError("Subclasses must implement execute_plan")
