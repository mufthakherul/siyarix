# SPDX-License-Identifier: AGPL-3.0-or-later
"""Event bus for component communication and observability."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

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
    type: EventType
    source: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = ""


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[EventType | None, list[HandlerFn]] = {}
        self._wildcard_handlers: list[HandlerFn] = []
        self._history: list[Event] = []
        self._max_history = 1000

    def on(self, event_type: EventType | None, handler: HandlerFn) -> None:
        if event_type is None:
            self._wildcard_handlers.append(handler)
        else:
            self._handlers.setdefault(event_type, []).append(handler)

    def off(self, event_type: EventType | None, handler: HandlerFn) -> None:
        if event_type is None:
            self._wildcard_handlers = [h for h in self._wildcard_handlers if h != handler]
        elif event_type in self._handlers:
            self._handlers[event_type] = [h for h in self._handlers[event_type] if h != handler]

    async def emit(self, event: Event) -> None:
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]
        handlers = list(self._wildcard_handlers)
        if event.type in self._handlers:
            handlers.extend(self._handlers[event.type])
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                logger.exception("Event handler error for %s", event.type)

    def get_history(self, event_type: EventType | None = None, limit: int = 50) -> list[Event]:
        if event_type:
            return [e for e in self._history if e.type == event_type][-limit:]
        return self._history[-limit:]

    def clear(self) -> None:
        self._history.clear()
        self._handlers.clear()
        self._wildcard_handlers.clear()


_bus: EventBus | None = None


def emit_sync(event: Event) -> None:
    """Fire-and-forget event emission from synchronous code."""
    bus = get_event_bus()
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(bus.emit(event))
    except RuntimeError:
        logger.debug("No running event loop; event dropped: %s", event.type)


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
