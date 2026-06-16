# SPDX-License-Identifier: AGPL-3.0-or-later
"""Context management with compression, retrieval, and optimization."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContextChunk:
    content: str
    chunk_id: str = ""
    source: str = ""
    token_estimate: int = 0
    priority: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.chunk_id:
            self.chunk_id = hashlib.sha256(self.content.encode()).hexdigest()[:12]
        if not self.token_estimate:
            self.token_estimate = max(1, len(self.content) // 4)


@dataclass
class ContextWindow:
    max_tokens: int = 1_000_000
    system_prompt_tokens: int = 0
    history_tokens: int = 0
    tool_output_tokens: int = 0
    reserved_tokens: int = 2000

    @property
    def available_tokens(self) -> int:
        used = self.system_prompt_tokens + self.history_tokens + self.tool_output_tokens
        return max(0, self.max_tokens - used - self.reserved_tokens)

    @property
    def usage_pct(self) -> float:
        if self.max_tokens <= 0:
            return 100.0
        used = self.system_prompt_tokens + self.history_tokens + self.tool_output_tokens
        return min(100.0, (used / self.max_tokens) * 100.0)

    @property
    def needs_compression(self) -> bool:
        return self.usage_pct > 80.0


class ContextManager:
    def __init__(self, max_tokens: int = 1_000_000, memory: Any = None) -> None:
        self._window = ContextWindow(max_tokens=max_tokens)
        self._chunks: list[ContextChunk] = []
        self._compressed_summaries: list[str] = []
        self._total_tokens = 0
        self._compression_count = 0
        self._memory = memory

        if self._memory and hasattr(self._memory, "load_context"):
            history = self._memory.load_context()
            for entry in history:
                role = entry.get("role", "user")
                content = entry.get("content", "")
                if content:
                    chunk = ContextChunk(content=content, source=f"history:{role}")
                    self._chunks.append(chunk)
                    self._window.history_tokens += chunk.token_estimate
                    self._total_tokens += chunk.token_estimate

    @property
    def window(self) -> ContextWindow:
        return self._window

    def add_system_prompt(self, content: str) -> None:
        self._window.system_prompt_tokens = max(1, len(content) // 4)

    def add_history(self, content: str, role: str = "user") -> None:
        chunk = ContextChunk(content=content, source=f"history:{role}")
        self._chunks.append(chunk)
        self._window.history_tokens += chunk.token_estimate
        self._total_tokens += chunk.token_estimate
        if self._memory and hasattr(self._memory, "save_context"):
            import time

            self._memory.save_context({"role": role, "content": content, "ts": time.time()})

    def add_tool_output(self, tool: str, output: str, max_length: int = 4000) -> None:
        truncated = output[:max_length] + ("..." if len(output) > max_length else "")
        chunk = ContextChunk(content=truncated, source=f"tool:{tool}")
        self._chunks.append(chunk)
        self._window.tool_output_tokens += chunk.token_estimate
        self._total_tokens += chunk.token_estimate

    def add_finding(self, finding: dict[str, Any]) -> None:
        content = f"[{finding.get('type', 'info')}] {finding.get('message', str(finding))}"
        chunk = ContextChunk(content=content, source="finding", priority=0.8)
        self._chunks.append(chunk)
        self._window.tool_output_tokens += chunk.token_estimate

    def should_compress(self) -> bool:
        return self._window.needs_compression

    def compress(self) -> str:
        if not self._chunks:
            return ""
        chunks_by_priority = sorted(self._chunks, key=lambda c: -c.priority)
        keep_count = max(3, len(chunks_by_priority) // 2)
        keep = chunks_by_priority[:keep_count]
        summarize = chunks_by_priority[keep_count:]
        summary_parts = [f"[{c.source}] {c.content[:200]}" for c in summarize]
        summary = "Context summary:\n" + "\n".join(summary_parts)
        self._compressed_summaries.append(summary)
        self._chunks = keep
        kept_tokens = sum(c.token_estimate for c in keep)
        compressed_tokens = sum(c.token_estimate for c in summarize) // 4
        self._window.history_tokens = kept_tokens + compressed_tokens
        self._compression_count += 1
        return summary

    def build_context(self) -> list[dict[str, str]]:
        messages = []
        if self._compressed_summaries:
            combined = "\n\n".join(self._compressed_summaries[-3:])
            messages.append({"role": "system", "content": f"Previous context:\n{combined}"})
        for chunk in self._chunks:
            if chunk.source.startswith("history:"):
                role = chunk.source.split(":", 1)[1]
                messages.append({"role": role, "content": chunk.content})
            elif chunk.source.startswith("tool:"):
                tool = chunk.source.split(":", 1)[1]
                messages.append({"role": "tool", "content": f"[{tool}] {chunk.content}"})
        return messages

    def get_history(self) -> list[dict[str, str]]:
        """Alias for build_context to maintain backward compatibility."""
        return self.build_context()

    def get_relevant_context(self, query: str, limit: int = 5) -> list[ContextChunk]:
        query_lower = query.lower()
        scored = []
        for chunk in self._chunks:
            score = chunk.priority + (2.0 if query_lower in chunk.content.lower() else 0.0)
            for word in query_lower.split():
                if word in chunk.content.lower():
                    score += 0.5
            if score > 0:
                scored.append((score, chunk))
        scored.sort(key=lambda x: -x[0])
        return [chunk for _, chunk in scored[:limit]]

    def clear(self) -> None:
        self._chunks.clear()
        self._compressed_summaries.clear()
        self._window.history_tokens = 0
        self._window.tool_output_tokens = 0
        self._total_tokens = 0

    def stats(self) -> dict[str, Any]:
        return {
            "total_chunks": len(self._chunks),
            "total_tokens": self._total_tokens,
            "usage_pct": round(self._window.usage_pct, 1),
            "needs_compression": self._window.needs_compression,
            "compressions": self._compression_count,
        }


def compress_context(ctx: dict[str, Any], max_tokens: int = 8000) -> dict[str, Any]:
    """Compress a context dict by truncating oversized fields."""
    result = dict(ctx)

    tools = result.get("available_tools")
    if isinstance(tools, list) and len(tools) > 20:
        truncated = len(tools) - 20
        result["available_tools"] = tools[:20]
        result["_tools_truncated"] = truncated

    history = result.get("conversation_history")
    if isinstance(history, str):
        lines = history.split("\n")
        if len(lines) > max_tokens:
            keep = max_tokens * 4 // 5
            truncated_count = len(lines) - keep
            result["conversation_history"] = "\n".join(lines[-keep:])
            result["_history_truncated"] = truncated_count

    xi = result.get("xi_context")
    if isinstance(xi, dict):
        execs = xi.get("recent_executions")
        if isinstance(execs, list) and len(execs) > 10:
            result["xi_context"] = {**xi, "recent_executions": execs[:10]}

    recs = result.get("xi_recommendations")
    if isinstance(recs, list) and len(recs) > 5:
        result["xi_recommendations"] = recs[:5]

    return result


__all__ = [
    "ContextChunk",
    "ContextWindow",
    "ContextManager",
    "compress_context",
]
