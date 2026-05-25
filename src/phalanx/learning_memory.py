"""
Learning Memory -- tool usage pattern learning and auto-suggestion.

As described in Chapter 10.1: learns tool chaining patterns
from successful executions and suggests them in future sessions.
"""
from __future__ import annotations

import json
import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PHALANX_HOME = Path.home() / ".phalanx"
_LEARNING_DIR = _PHALANX_HOME / "learning"


@dataclass
class ToolPattern:
    tools: list[str]
    count: int = 1
    last_used: str = ""
    avg_duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "tools": self.tools,
            "count": self.count,
            "last_used": self.last_used,
            "avg_duration_ms": self.avg_duration_ms,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolPattern:
        return cls(
            tools=data.get("tools", []),
            count=data.get("count", 1),
            last_used=data.get("last_used", ""),
            avg_duration_ms=data.get("avg_duration_ms", 0.0),
        )


class LearningMemory:
    """Persistent learning memory for tool patterns."""

    def __init__(self):
        _LEARNING_DIR.mkdir(parents=True, exist_ok=True)
        self._patterns_path = _LEARNING_DIR / "tool_patterns.json"
        self._patterns: list[ToolPattern] = []
        self._load()

    def _load(self) -> None:
        if self._patterns_path.exists():
            try:
                with open(str(self._patterns_path)) as f:
                    data = json.load(f)
                self._patterns = [ToolPattern.from_dict(d) for d in data.get("patterns", [])]
            except Exception as exc:
                logger.warning("Failed to load learning patterns: %s", exc)

    def _save(self) -> None:
        try:
            with open(str(self._patterns_path), "w") as f:
                json.dump({"patterns": [p.to_dict() for p in self._patterns]}, f, indent=2)
        except Exception as exc:
            logger.warning("Failed to save learning patterns: %s", exc)

    def record(self, tools: list[str], duration_ms: float = 0.0) -> None:
        """Record a successful tool chain."""
        key = " -> ".join(tools)
        for pattern in self._patterns:
            if " -> ".join(pattern.tools) == key:
                pattern.count += 1
                pattern.last_used = datetime.now().isoformat()
                pattern.avg_duration_ms = (pattern.avg_duration_ms * (pattern.count - 1) + duration_ms) / pattern.count
                self._save()
                return
        self._patterns.append(ToolPattern(
            tools=tools,
            count=1,
            last_used=datetime.now().isoformat(),
            avg_duration_ms=duration_ms,
        ))
        self._save()

    def suggest(self, current_tool: str) -> list[str]:
        """Suggest next tools based on learned patterns."""
        suggestions: list[str] = []
        for pattern in sorted(self._patterns, key=lambda p: p.count, reverse=True):
            if current_tool in pattern.tools:
                idx = pattern.tools.index(current_tool)
                if idx + 1 < len(pattern.tools):
                    suggestions.append(pattern.tools[idx + 1])
            if len(suggestions) >= 3:
                break
        return suggestions

    def top_patterns(self, n: int = 5) -> list[ToolPattern]:
        return sorted(self._patterns, key=lambda p: p.count, reverse=True)[:n]

    @property
    def total_records(self) -> int:
        return len(self._patterns)

__all__ = ["LearningMemory", "ToolPattern"]
