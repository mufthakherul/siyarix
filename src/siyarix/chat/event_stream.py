"""Granular assistant message event stream.

Provides typed events for each content block lifecycle phase:
  text_start, text_delta, text_end
  thinking_start, thinking_delta, thinking_end
  toolcall_start, toolcall_delta, toolcall_end
  start, error, done
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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


