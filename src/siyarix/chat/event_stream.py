"""Granular assistant message event stream.

OpenClaw pattern: AssistantMessageEventStream in llm/utils/event-stream.ts
Provides typed events for each content block lifecycle phase:
  text_start, text_delta, text_end
  thinking_start, thinking_delta, thinking_end
  toolcall_start, toolcall_delta, toolcall_end
  start, error, done
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Callable


# ── Event types ────────────────────────────────────────────────────────


class EventType(str, Enum):
    START = "start"
    ERROR = "error"
    DONE = "done"
    TEXT_START = "text_start"
    TEXT_DELTA = "text_delta"
    TEXT_END = "text_end"
    THINKING_START = "thinking_start"
    THINKING_DELTA = "thinking_delta"
    THINKING_END = "thinking_end"
    TOOLCALL_START = "toolcall_start"
    TOOLCALL_DELTA = "toolcall_delta"
    TOOLCALL_END = "toolcall_end"


# ── Data types ─────────────────────────────────────────────────────────


@dataclass
class TextContent:
    text: str = ""


@dataclass
class ThinkingContent:
    thinking: str = ""
    thinking_signature: str = ""
    redacted: bool = False


@dataclass
class ToolCallContent:
    id: str = ""
    name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)


ContentBlock = TextContent | ThinkingContent | ToolCallContent


@dataclass
class Usage:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0
    total_tokens: int = 0


@dataclass
class AssistantMessage:
    role: str = "assistant"
    content: list[ContentBlock] = field(default_factory=list)
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = "stop"
    error_message: str = ""


# ── Events ─────────────────────────────────────────────────────────────


@dataclass
class StreamEvent:
    type: EventType
    content_index: int = -1
    delta: str = ""
    content: str = ""
    tool_call: ToolCallContent | None = None
    partial: AssistantMessage | None = None
    reason: str = ""
    message: AssistantMessage | None = None
    error: AssistantMessage | None = None


# ── Consumer types ─────────────────────────────────────────────────────

EventHandler = Callable[[StreamEvent], None]


# ── Event Stream ───────────────────────────────────────────────────────


class AssistantMessageEventStream:
    """Typed event stream for assistant message generation.

    Producers push events via ``push()`` and signal completion via ``end()``.
    Consumers iterate via ``events()`` or attach a handler with ``on_event()``.

    Events (in order for a normal response):
      1. ``START`` — response begins
      2. ``TEXT_START`` / ``THINKING_START`` / ``TOOLCALL_START`` — block begins
      3. ``TEXT_DELTA`` / ``THINKING_DELTA`` / ``TOOLCALL_DELTA`` — content streaming
      4. ``TEXT_END`` / ``THINKING_END`` / ``TOOLCALL_END`` — block finishes
      5. Repeat 2-4 for each block
      6. ``DONE`` — response complete

    On error:
      1. ``START``
      2. ``ERROR`` — with error message
    """

    def __init__(self) -> None:
        self._events: list[StreamEvent] = []
        self._handlers: list[EventHandler] = []
        self._done = False
        self._error: Exception | None = None

    def push(self, event: StreamEvent) -> None:
        """Push an event to the stream."""
        self._events.append(event)
        for handler in self._handlers:
            handler(event)

    def end(self) -> None:
        """Mark the stream as complete."""
        self._done = True

    def on_event(self, handler: EventHandler) -> Callable[[], None]:
        """Register an event handler. Returns a deregistration callable."""
        self._handlers.append(handler)
        return lambda: self._handlers.remove(handler)

    @property
    def done(self) -> bool:
        return self._done

    def events(self) -> list[StreamEvent]:
        """Return all events emitted so far."""
        return list(self._events)

    def __aiter__(self) -> AsyncIterator[StreamEvent]:
        """Async iteration yields events as they arrive."""
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[StreamEvent]:
        index = 0
        while not self._done or index < len(self._events):
            if index < len(self._events):
                yield self._events[index]
                index += 1
            else:
                import asyncio

                await asyncio.sleep(0.01)

    # ── Convenience helpers ──────────────────────────────────────────

    @property
    def text(self) -> str:
        """Concatenate all text deltas into a single string."""
        parts: list[str] = []
        for event in self._events:
            if event.type == EventType.TEXT_DELTA:
                parts.append(event.delta)
        return "".join(parts)

    @property
    def thinking(self) -> str:
        """Concatenate all thinking deltas."""
        parts: list[str] = []
        for event in self._events:
            if event.type == EventType.THINKING_DELTA:
                parts.append(event.delta)
        return "".join(parts)

    @property
    def tool_calls(self) -> list[ToolCallContent]:
        """Return all completed tool calls."""
        calls: list[ToolCallContent] = []
        for event in self._events:
            if event.type == EventType.TOOLCALL_END and event.tool_call:
                calls.append(event.tool_call)
        return calls

    @property
    def final_message(self) -> AssistantMessage | None:
        """Return the final message if the stream completed."""
        for event in self._events:
            if event.type == EventType.DONE and event.message:
                return event.message
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialise the stream to a dict for logging/debugging."""
        return {
            "events": [self._event_to_dict(e) for e in self._events],
            "text": self.text,
            "thinking": self.thinking,
            "tool_calls": [
                {"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in self.tool_calls
            ],
        }

    def _event_to_dict(self, event: StreamEvent) -> dict[str, Any]:
        d: dict[str, Any] = {"type": event.type.value}
        if event.content_index >= 0:
            d["content_index"] = event.content_index
        if event.delta:
            d["delta"] = event.delta
        if event.content:
            d["content"] = event.content
        if event.tool_call:
            d["tool_call"] = {"id": event.tool_call.id, "name": event.tool_call.name}
        if event.reason:
            d["reason"] = event.reason
        return d

    def to_json(self) -> str:
        """Serialise to JSON."""
        return json.dumps(self.to_dict(), indent=2)
