"""Performance optimization and resource profiling module.

Monitors system resources, auto-tunes agent pool sizes, memory limits,
CPU affinity, and network throttling based on available hardware and
current workload characteristics.
"""

from __future__ import annotations

import json
import logging
import os
import platform as _platform
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SystemResources:
    cpu_cores: int = 0
    cpu_logical: int = 0
    total_ram_gb: float = 0.0
    available_ram_gb: float = 0.0
    platform: str = ""
    architecture: str = ""

    @property
    def recommended_max_agents(self) -> int:
        return max(1, min(self.cpu_logical * 2, 32))

    @property
    def recommended_memory_per_agent_mb(self) -> int:
        if self.total_ram_gb >= 64:
            return 4096
        elif self.total_ram_gb >= 32:
            return 2048
        elif self.total_ram_gb >= 16:
            return 1024
        elif self.total_ram_gb >= 8:
            return 512
        return 256

    @property
    def recommended_concurrent_tools(self) -> int:
        return max(1, self.cpu_logical // 2)


@dataclass
class PerformanceConfig:
    max_concurrent_agents: int = 15
    memory_limit_per_agent_mb: int = 2048
    cpu_affinity: str = "auto-balanced"
    network_throttling: bool = False
    network_bandwidth_limit_mbps: int = 0
    enable_parallel_scanning: bool = True
    enable_caching: bool = True
    enable_progress_tracking: bool = True
    log_level: str = "INFO"


class PerformanceOptimizer:
    """System-aware performance tuning and resource management."""

    def __init__(self) -> None:
        self._config = PerformanceConfig()
        self._resources = self._detect_resources()

    def _detect_resources(self) -> SystemResources:
        try:
            import psutil
            cpu_logical = psutil.cpu_count(logical=True) or 1
            cpu_cores = psutil.cpu_count(logical=False) or 1
            mem = psutil.virtual_memory()
            total_gb = mem.total / (1024 ** 3)
            avail_gb = mem.available / (1024 ** 3)
        except ImportError:
            cpu_logical = os.cpu_count() or 1
            cpu_cores = cpu_logical
            total_gb = 8.0
            avail_gb = 4.0

        return SystemResources(
            cpu_cores=cpu_cores,
            cpu_logical=cpu_logical,
            total_ram_gb=round(total_gb, 1),
            available_ram_gb=round(avail_gb, 1),
            platform=_platform.system(),
            architecture=_platform.machine(),
        )

    @property
    def resources(self) -> SystemResources:
        return self._resources

    @property
    def config(self) -> PerformanceConfig:
        return self._config

    def auto_tune(self) -> PerformanceConfig:
        """Automatically configure performance parameters based on hardware."""
        self._config.max_concurrent_agents = self._resources.recommended_max_agents
        self._config.memory_limit_per_agent_mb = self._resources.recommended_memory_per_agent_mb
        self._config.enable_parallel_scanning = self._resources.cpu_logical >= 4
        self._config.enable_caching = True
        logger.info(
            "Auto-tuned: agents=%d memory=%dMB parallel=%s",
            self._config.max_concurrent_agents,
            self._config.memory_limit_per_agent_mb,
            self._config.enable_parallel_scanning,
        )
        return self._config

    def configure(self, **kwargs: Any) -> PerformanceConfig:
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
        return self._config

    def summary(self) -> dict[str, Any]:
        return {
            "resources": {
                "cpu_cores": self._resources.cpu_cores,
                "cpu_logical": self._resources.cpu_logical,
                "ram_gb": self._resources.total_ram_gb,
                "ram_available_gb": self._resources.available_ram_gb,
                "platform": self._resources.platform,
                "architecture": self._resources.architecture,
            },
            "config": {
                "max_concurrent_agents": self._config.max_concurrent_agents,
                "memory_per_agent_mb": self._config.memory_limit_per_agent_mb,
                "cpu_affinity": self._config.cpu_affinity,
                "network_throttling": self._config.network_throttling,
                "parallel_scanning": self._config.enable_parallel_scanning,
                "caching": self._config.enable_caching,
            },
            "recommended": {
                "max_agents": self._resources.recommended_max_agents,
                "memory_per_agent_mb": self._resources.recommended_memory_per_agent_mb,
                "concurrent_tools": self._resources.recommended_concurrent_tools,
            },
        }


performance_optimizer = PerformanceOptimizer()


__all__ = ["PerformanceOptimizer", "PerformanceConfig", "SystemResources", "performance_optimizer"]
