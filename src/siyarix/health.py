# SPDX-License-Identifier: AGPL-3.0-or-later

"""Health check utilities for system diagnostics."""

from __future__ import annotations

import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["HealthStatus", "HealthChecker", "get_health"]


class HealthState(StrEnum):
    """Health states."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Health status of a component."""

    name: str
    state: HealthState
    message: str = ""
    latency_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class HealthStatus:
    """Overall system health status."""

    state: HealthState
    components: list[ComponentHealth] = field(default_factory=list)
    checks_performed: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    uptime_seconds: float = 0.0

    @property
    def is_healthy(self) -> bool:
        """Check if system is healthy."""
        return self.state == HealthState.HEALTHY

    @property
    def is_degraded(self) -> bool:
        """Check if system is degraded."""
        return self.state == HealthState.DEGRADED

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "state": self.state.value,
            "is_healthy": self.is_healthy,
            "is_degraded": self.is_degraded,
            "uptime_seconds": self.uptime_seconds,
            "checks_performed": self.checks_performed,
            "components": [
                {
                    "name": c.name,
                    "state": c.state.value,
                    "message": c.message,
                    "latency_ms": c.latency_ms,
                    "details": c.details,
                }
                for c in self.components
            ],
            "timestamp": self.timestamp.isoformat(),
        }


class HealthChecker:
    """System health checker."""

    _instance: HealthChecker | None = None

    def __init__(self) -> None:
        self.start_time = time.time()
        self.last_check: HealthStatus | None = None
        self.model_providers_available: dict[str, bool] = {}
        self.tools_available: dict[str, bool] = {}

    @classmethod
    def instance(cls) -> HealthChecker:
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def check_all(self) -> HealthStatus:
        """Perform comprehensive health check."""
        status = HealthStatus(state=HealthState.HEALTHY)
        status.uptime_seconds = time.time() - self.start_time

        # Check model providers
        await self._check_model_providers(status)

        # Check tool registry
        await self._check_tool_registry(status)

        # Check system resources
        await self._check_system_resources(status)

        # Determine overall state
        unhealthy = sum(
            1 for c in status.components if c.state == HealthState.UNHEALTHY
        )
        degraded = sum(1 for c in status.components if c.state == HealthState.DEGRADED)

        if unhealthy > 0:
            status.state = HealthState.UNHEALTHY
        elif degraded > 0:
            status.state = HealthState.DEGRADED
        else:
            status.state = HealthState.HEALTHY

        status.checks_performed = len(status.components)
        status.timestamp = datetime.now(UTC)

        self.last_check = status
        return status

    async def _check_model_providers(self, status: HealthStatus) -> None:
        """Check model provider health."""
        providers_to_check = {
            "OpenAI": {"requires_env": "OPENAI_API_KEY"},
            "Gemini": {"requires_env": "GEMINI_API_KEY"},
            "Ollama": {"requires_running": True},
            "Cloud": {"requires_config": True},
            "OpenRouter": {"requires_env": "OPENROUTER_API_KEY"},
        }

        for provider_name, config in providers_to_check.items():
            start = time.time()
            try:
                available = False
                message = ""

                if provider_name == "OpenAI":
                    available = bool(os.getenv("OPENAI_API_KEY"))
                    message = (
                        "OpenAI API key configured"
                        if available
                        else "OpenAI not configured"
                    )

                elif provider_name == "Gemini":
                    available = bool(
                        os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
                    )
                    message = (
                        "Gemini API key configured"
                        if available
                        else "Gemini not configured"
                    )

                elif provider_name == "Ollama":
                    # Check if Ollama is running
                    try:
                        import httpx

                        async with httpx.AsyncClient(timeout=2.0) as client:
                            resp = await client.get("http://localhost:11434/api/tags")
                            available = resp.status_code == 200
                            message = (
                                "Ollama responsive"
                                if available
                                else "Ollama not responding"
                            )
                    except Exception:
                        logger.debug("Ollama check failed — not running")
                        available = False
                        message = "Ollama not running"

                elif provider_name == "Cloud":
                    # Check if cloud config present
                    available = bool(
                        os.getenv("SIYARIX_SERVER_URL") and os.getenv("SIYARIX_API_KEY")
                    )
                    message = (
                        "Cloud configured" if available else "Cloud not configured"
                    )

                elif provider_name == "OpenRouter":
                    available = bool(os.getenv("OPENROUTER_API_KEY"))
                    message = (
                        "OpenRouter API key configured"
                        if available
                        else "OpenRouter not configured"
                    )

                self.model_providers_available[provider_name] = available

                latency = (time.time() - start) * 1000
                status.components.append(
                    ComponentHealth(
                        name=f"ModelProvider/{provider_name}",
                        state=(
                            HealthState.HEALTHY if available else HealthState.DEGRADED
                        ),
                        message=message,
                        latency_ms=latency,
                        details={"available": available},
                    )
                )
            except Exception as exc:
                logger.exception("Model provider check failed for %s", provider_name)
                status.components.append(
                    ComponentHealth(
                        name=f"ModelProvider/{provider_name}",
                        state=HealthState.UNHEALTHY,
                        message=f"Error: {str(exc)}",
                        latency_ms=(time.time() - start) * 1000,
                    )
                )

    async def _check_tool_registry(self, status: HealthStatus) -> None:
        """Check tool registry health."""
        critical_tools = ["bash", "sh", "python", "python3"]
        found_tools = []

        for tool in critical_tools:
            start = time.time()
            try:
                path = shutil.which(tool)
                available = path is not None
                self.tools_available[tool] = available

                if available:
                    found_tools.append(tool)

                latency = (time.time() - start) * 1000
                status.components.append(
                    ComponentHealth(
                        name=f"Tool/{tool}",
                        state=(
                            HealthState.HEALTHY if available else HealthState.DEGRADED
                        ),
                        message=(
                            f"{'Found' if available else 'Not found'} at {path}"
                            if available
                            else "Not in PATH"
                        ),
                        latency_ms=latency,
                    )
                )
            except Exception as exc:
                logger.exception("Tool registry check failed for %s", tool)
                status.components.append(
                    ComponentHealth(
                        name=f"Tool/{tool}",
                        state=HealthState.UNHEALTHY,
                        message=f"Error: {str(exc)}",
                        latency_ms=(time.time() - start) * 1000,
                    )
                )

        # Overall tool registry status
        if len(found_tools) == len(critical_tools):
            registry_state = HealthState.HEALTHY
        elif len(found_tools) > 0:
            registry_state = HealthState.DEGRADED
        else:
            registry_state = HealthState.UNHEALTHY

        status.components.append(
            ComponentHealth(
                name="ToolRegistry",
                state=registry_state,
                message=f"Found {len(found_tools)}/{len(critical_tools)} critical tools",
                details={
                    "found": found_tools,
                    "missing": [t for t in critical_tools if t not in found_tools],
                },
            )
        )

    async def _check_system_resources(self, status: HealthStatus) -> None:
        """Check system resources."""
        try:
            import psutil

            # Memory
            memory = psutil.virtual_memory()
            mem_state = (
                HealthState.HEALTHY
                if memory.percent < 80
                else (
                    HealthState.DEGRADED
                    if memory.percent < 95
                    else HealthState.UNHEALTHY
                )
            )
            status.components.append(
                ComponentHealth(
                    name="SystemMemory",
                    state=mem_state,
                    message=f"Memory usage: {memory.percent:.1f}%",
                    details={
                        "used_gb": memory.used / (1024**3),
                        "total_gb": memory.total / (1024**3),
                        "percent": memory.percent,
                    },
                )
            )

            # Disk
            disk = psutil.disk_usage("/")
            disk_state = (
                HealthState.HEALTHY
                if disk.percent < 80
                else (
                    HealthState.DEGRADED if disk.percent < 95 else HealthState.UNHEALTHY
                )
            )
            status.components.append(
                ComponentHealth(
                    name="SystemDisk",
                    state=disk_state,
                    message=f"Disk usage: {disk.percent:.1f}%",
                    details={
                        "used_gb": disk.used / (1024**3),
                        "total_gb": disk.total / (1024**3),
                        "percent": disk.percent,
                    },
                )
            )

            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_state = (
                HealthState.HEALTHY
                if cpu_percent < 80
                else (
                    HealthState.DEGRADED if cpu_percent < 95 else HealthState.UNHEALTHY
                )
            )
            status.components.append(
                ComponentHealth(
                    name="SystemCPU",
                    state=cpu_state,
                    message=f"CPU usage: {cpu_percent:.1f}%",
                    details={"cpu_percent": cpu_percent},
                )
            )
        except ImportError:
            # psutil not available; skip system resource checks
            pass


def get_health() -> HealthChecker:
    """Get health checker instance."""
    return HealthChecker.instance()
