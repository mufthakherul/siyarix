"""Dashboard data models for Phalanx CLI dashboards."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    refresh_interval: int = 5
    enable_cors: bool = True
    auth_token: str = ""
    max_history: int = 100


@dataclass
class DashboardSnapshot:
    timestamp: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    active_scans: list[dict[str, Any]] = field(default_factory=list)
    recent_findings: list[dict[str, Any]] = field(default_factory=list)
    graph_stats: dict[str, Any] = field(default_factory=dict)
    system_health: dict[str, Any] = field(default_factory=dict)
    agent_status: list[dict[str, Any]] = field(default_factory=list)
    top_tools: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp or datetime.now().isoformat(),
            "metrics": self.metrics,
            "active_scans": self.active_scans[:20],
            "recent_findings": self.recent_findings[:50],
            "graph_stats": self.graph_stats,
            "system_health": self.system_health,
            "agent_status": self.agent_status,
            "top_tools": self.top_tools[:10],
        }


__all__ = [
    "DashboardSnapshot",
    "DashboardConfig",
]
