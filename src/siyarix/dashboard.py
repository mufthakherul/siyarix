"""Dashboard data models and live snapshot service for Siyarix CLI.

Provides data models for real-time operational dashboards and a
DashboardService to collect system metrics, agent status, and findings
into structured snapshots.
"""

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
            "agent_status": self.agent_status[:20],
            "top_tools": self.top_tools[:10],
        }


class DashboardService:
    """Collects metrics, health, and findings into live snapshots."""

    def __init__(self, config: DashboardConfig | None = None) -> None:
        self._config = config or DashboardConfig()
        self._snapshots: list[DashboardSnapshot] = []

    def collect_snapshot(self) -> DashboardSnapshot:
        snapshot = DashboardSnapshot(timestamp=datetime.now().isoformat())
        try:
            from .health import get_health
            health = get_health()
            import asyncio
            health_result = asyncio.run(health.check_all())
            snapshot.system_health = {
                "state": health_result.state.value,
                "components": [
                    {"name": c.name, "state": c.state.value, "latency_ms": c.latency_ms}
                    for c in health_result.components
                ],
            }
        except Exception:
            snapshot.system_health = {"state": "unknown"}

        try:
            from .metrics import get_metrics
            metrics = get_metrics()
            snapshot.metrics = metrics.to_dict()
        except Exception:
            snapshot.metrics = {}

        self._snapshots.append(snapshot)
        if len(self._snapshots) > self._config.max_history:
            self._snapshots = self._snapshots[-self._config.max_history:]
        return snapshot

    @property
    def latest(self) -> DashboardSnapshot | None:
        return self._snapshots[-1] if self._snapshots else None

    @property
    def history(self) -> list[DashboardSnapshot]:
        return list(self._snapshots)


__all__ = [
    "DashboardSnapshot",
    "DashboardConfig",
    "DashboardService",
]
