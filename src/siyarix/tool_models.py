# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data models for the tool registry."""

from __future__ import annotations

import functools
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Coroutine

ToolHandler = Callable[..., Coroutine[Any, Any, dict[str, Any]]]


class ToolCategory(StrEnum):
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"
    UTILITY = "utility"
    NETWORK = "network"
    WEB = "web"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    CONTAINER = "container"
    CLOUD = "cloud"
    DEVSECOPS = "devsecops"


class RiskLevel(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_TOOL_WHICH_CACHE: dict[str, str | None] = {}


@functools.lru_cache(maxsize=1024)
def _cached_which(name: str) -> str | None:
    result = shutil.which(name)
    _TOOL_WHICH_CACHE[name] = result
    return result


def invalidate_which_cache() -> None:
    _TOOL_WHICH_CACHE.clear()
    _cached_which.cache_clear()


@dataclass
class ToolCapability:
    name: str
    description: str = ""
    category: ToolCategory = ToolCategory.UTILITY
    risk_level: RiskLevel = RiskLevel.SAFE
    aliases: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    inputs: dict[str, str] = field(default_factory=dict)
    input_schema: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    related_tools: list[str] = field(default_factory=list)
    workflows: list[str] = field(default_factory=list)
    binary: str = ""
    version: str = ""
    installed: bool = False
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    parser: str = ""
    availability: dict[str, Any] | None = None
    usage_count: int = 0
    last_used: float = 0.0
    avg_duration_ms: float = 0.0

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ToolCapability):
            return NotImplemented
        return self.name == other.name

    @property
    def is_available(self) -> bool:
        if not self.installed and self.binary:
            return _cached_which(self.binary) is not None
        return self.installed


@dataclass
class ToolEdge:
    source: str
    target: str
    relation: str = "chain"
    weight: float = 1.0

__all__ = [
    "ToolCategory",
    "RiskLevel",
    "ToolCapability",
    "ToolEdge",
]
