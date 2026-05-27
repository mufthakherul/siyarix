"""Context building and compression for the execution engine."""

from __future__ import annotations

from typing import Any


def compress_context(
    context: dict[str, Any],
    max_tokens: int = 8000,
) -> dict[str, Any]:
    """Compress context window by summarizing verbose fields.

    Truncates large tool descriptions, conversation history, and
    XI context when approaching LLM token limits. Preserves the
    most recent and highest-priority information.
    """
    compressed = dict(context)

    tools = compressed.get("available_tools", [])
    if isinstance(tools, list) and len(tools) > 20:
        compressed["available_tools"] = tools[:20]
        compressed["_tools_truncated"] = len(tools) - 20

    history = compressed.get("conversation_history", "")
    if isinstance(history, str) and len(history) > max_tokens:
        lines = history.split("\n")
        compressed["conversation_history"] = "\n".join(lines[-40:])
        compressed["_history_truncated"] = len(lines) - 40

    xi = compressed.get("xi_context", {})
    if isinstance(xi, dict) and xi.get("recent_executions"):
        xi["recent_executions"] = xi["recent_executions"][-10:]
        compressed["xi_context"] = xi

    recs = compressed.get("xi_recommendations", [])
    if isinstance(recs, list) and len(recs) > 5:
        compressed["xi_recommendations"] = recs[:5]

    return compressed
