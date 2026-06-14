# SPDX-License-Identifier: AGPL-3.0-or-later
"""Event bus for component communication and observability."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "Event",
    "EventBus",
    "EventType",
    "HandlerFn",
    "emit_sync",
    "get_event_bus",
]

HandlerFn = Callable[["Event"], Coroutine[Any, Any, None]]


class EventType(StrEnum):
    AGENT_START = "agent.start"
    AGENT_STOP = "agent.stop"
    AGENT_ERROR = "agent.error"
    PLAN_CREATED = "plan.created"
    PLAN_STEP_START = "plan.step.start"
    PLAN_STEP_COMPLETE = "plan.step.complete"
    PLAN_STEP_FAILED = "plan.step.failed"
    PLAN_COMPLETE = "plan.complete"
    TOOL_REGISTERED = "tool.registered"
    TOOL_EXECUTING = "tool.executing"
    TOOL_COMPLETE = "tool.complete"
    TOOL_FAILED = "tool.failed"
    TOOL_NOT_FOUND = "tool.not_found"
    PROVIDER_SELECTED = "provider.selected"
    PROVIDER_FALLBACK = "provider.fallback"
    PROVIDER_ERROR = "provider.error"
    MEMORY_STORED = "memory.stored"
    MEMORY_RETRIEVED = "memory.retrieved"
    CONTEXT_COMPRESSED = "context.compressed"
    WORKFLOW_START = "workflow.start"
    WORKFLOW_STEP = "workflow.step"
    WORKFLOW_COMPLETE = "workflow.complete"
    VALIDATION_PASSED = "validation.passed"
    VALIDATION_FAILED = "validation.failed"
    RECOVERY_ATTEMPT = "recovery.attempt"
    RECOVERY_SUCCESS = "recovery.success"
    MCP_CONNECTED = "mcp.connected"
    MCP_DISCONNECTED = "mcp.disconnected"
    CONFIG_CHANGED = "config.changed"
    HEARTBEAT = "heartbeat"
    CUSTOM = "custom"


@dataclass
class Event:
    """Represents a single event flowing through the :class:`EventBus`."""

    type: EventType
    source: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: str = ""

    @property
    def timestamp_dt(self) -> datetime:
        """Return the timestamp as a timezone-aware UTC :class:`datetime`."""
        return self.timestamp


class EventBus:
    """Async-first event bus for component communication and observability.

    History is stored in a bounded :class:`~collections.deque` so it can never
    grow beyond *max_history* entries, even between explicit trims.
    """

    _DEFAULT_MAX_HISTORY: int = 1000

    def __init__(self, *, max_history: int = _DEFAULT_MAX_HISTORY) -> None:
        self._handlers: dict[EventType | None, list[HandlerFn]] = {}
        self._wildcard_handlers: list[HandlerFn] = []
        self._history: deque[Event] = deque(maxlen=max_history)
        self._max_history: int = max_history
        self._lock = threading.Lock()

    def on(self, event_type: EventType | None, handler: HandlerFn) -> None:
        """Register *handler* for *event_type* (``None`` = wildcard)."""
        with self._lock:
            if event_type is None:
                self._wildcard_handlers.append(handler)
            else:
                self._handlers.setdefault(event_type, []).append(handler)

    def off(self, event_type: EventType | None, handler: HandlerFn) -> None:
        """Unregister *handler* from *event_type* (``None`` = wildcard)."""
        with self._lock:
            if event_type is None:
                self._wildcard_handlers = [h for h in self._wildcard_handlers if h != handler]
            elif event_type in self._handlers:
                self._handlers[event_type] = [h for h in self._handlers[event_type] if h != handler]

    async def emit(self, event: Event) -> None:
        """Emit *event* to all matching handlers and record it in history."""
        with self._lock:
            self._history.append(event)
            handlers = list(self._wildcard_handlers)
            if event.type in self._handlers:
                handlers.extend(self._handlers[event.type])
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                logger.exception("Event handler error for %s", event.type)

    def get_history(
        self,
        event_type: EventType | None = None,
        limit: int = 50,
    ) -> list[Event]:
        """Return recent events, optionally filtered by *event_type*."""
        with self._lock:
            if event_type is not None:
                return [e for e in self._history if e.type == event_type][-limit:]
            return list(self._history)[-limit:]

    # -- clearing helpers ----------------------------------------------------

    def clear_history(self) -> None:
        """Remove recorded events but keep all registered handlers."""
        with self._lock:
            self._history.clear()

    def clear_all(self) -> None:
        """Remove recorded events **and** all registered handlers."""
        with self._lock:
            self._history.clear()
            self._handlers.clear()
            self._wildcard_handlers.clear()

    def clear(self) -> None:
        """Alias for :meth:`clear_history` — prevents accidental handler deletion."""
        self.clear_history()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_bus: EventBus | None = None
_bus_lock: threading.Lock = threading.Lock()


def _task_exception_callback(task: asyncio.Task[None]) -> None:
    """Log exceptions from fire-and-forget event tasks created by :func:`emit_sync`."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("emit_sync task failed: %s", exc, exc_info=exc)


def emit_sync(event: Event) -> None:
    """Fire-and-forget event emission from synchronous code.

    A done-callback is attached to the created task so that exceptions are
    logged instead of silently swallowed.
    """
    bus = get_event_bus()
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(bus.emit(event))
        task.add_done_callback(_task_exception_callback)
    except RuntimeError:
        try:
            asyncio.run(bus.emit(event))
        except Exception as exc:
            logger.debug("Failed to run event loop for emit_sync: %s", exc)


def get_event_bus() -> EventBus:
    """Return the module-level :class:`EventBus` singleton (thread-safe).

    Uses double-checked locking to avoid acquiring the lock on the fast path
    once the singleton has been created.
    """
    global _bus  # noqa: PLW0603
    if _bus is None:
        with _bus_lock:
            if _bus is None:
                _bus = EventBus()
    return _bus


def reset_event_bus() -> None:
    """Replace the singleton with a fresh :class:`EventBus` — **testing only**."""
    global _bus  # noqa: PLW0603
    with _bus_lock:
        _bus = None
