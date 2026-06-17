# SPDX-License-Identifier: AGPL-3.0-or-later

"""Comprehensive tests for siyarix.performance — performance optimization & resource profiling."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from siyarix.performance import (
    PerformanceConfig,
    PerformanceOptimizer,
    performance_optimizer,
    SystemResources,
)


# ── SystemResources ──────────────────────────────────────────────────────

class TestSystemResources:
    def test_defaults(self) -> None:
        sr = SystemResources()
        assert sr.cpu_cores == 0
        assert sr.cpu_logical == 0
        assert sr.total_ram_gb == 0.0
        assert sr.available_ram_gb == 0.0
        assert sr.platform == ""
        assert sr.architecture == ""

    @pytest.mark.parametrize(
        "logical, ram_gb, expected",
        [
            (1, 2, 1),
            (2, 4, 2),
            (4, 8, 4),
            (8, 16, 8),
            (16, 32, 16),
            (32, 128, 64),
            (64, 256, 64),
            (128, 512, 64),  # capped at 64
        ],
    )
    def test_recommended_max_agents(self, logical: int, ram_gb: float, expected: int) -> None:
        sr = SystemResources(cpu_logical=logical, total_ram_gb=ram_gb)
        assert sr.recommended_max_agents == expected

    def test_recommended_max_agents_min_1(self) -> None:
        sr = SystemResources(cpu_logical=0, total_ram_gb=0.5)
        assert sr.recommended_max_agents == 1

    @pytest.mark.parametrize(
        "ram_gb, expected",
        [
            (128, 4096),
            (64, 4096),
            (48, 2048),
            (32, 2048),
            (24, 1024),
            (16, 1024),
            (12, 512),
            (8, 512),
            (4, 256),
            (2, 256),
            (0.5, 256),
        ],
    )
    def test_recommended_memory_per_agent_mb(self, ram_gb: float, expected: int) -> None:
        sr = SystemResources(total_ram_gb=ram_gb)
        assert sr.recommended_memory_per_agent_mb == expected

    @pytest.mark.parametrize(
        "logical, expected",
        [
            (0, 1),
            (1, 1),
            (2, 1),
            (4, 2),
            (8, 4),
            (16, 8),
        ],
    )
    def test_recommended_concurrent_tools(self, logical: int, expected: int) -> None:
        sr = SystemResources(cpu_logical=logical)
        assert sr.recommended_concurrent_tools == expected

    def test_cached_properties_are_cached(self) -> None:
        sr = SystemResources(cpu_logical=8, total_ram_gb=32)
        v1 = sr.recommended_max_agents
        v2 = sr.recommended_max_agents
        assert v1 == v2


# ── PerformanceConfig ────────────────────────────────────────────────────

class TestPerformanceConfig:
    def test_defaults(self) -> None:
        c = PerformanceConfig()
        assert c.max_concurrent_agents == 15
        assert c.memory_limit_per_agent_mb == 2048
        assert c.cpu_affinity == "auto-balanced"
        assert c.network_throttling is False
        assert c.network_bandwidth_limit_mbps == 0
        assert c.enable_parallel_scanning is True
        assert c.enable_caching is True
        assert c.enable_progress_tracking is True
        assert c.log_level == "INFO"

    def test_custom_values(self) -> None:
        c = PerformanceConfig(max_concurrent_agents=5, log_level="DEBUG")
        assert c.max_concurrent_agents == 5
        assert c.log_level == "DEBUG"


# ── PerformanceOptimizer ─────────────────────────────────────────────────

class TestPerformanceOptimizerDetectResources:
    @patch("psutil.cpu_count")
    @patch("psutil.virtual_memory")
    def test_with_psutil(self, mock_vmem: MagicMock, mock_cpu: MagicMock) -> None:
        mock_cpu.side_effect = lambda logical=True: 8 if logical else 4
        mock_vmem.return_value.total = 32 * 1024**3
        mock_vmem.return_value.available = 16 * 1024**3
        opt = PerformanceOptimizer()
        r = opt.resources
        assert r.cpu_cores == 4
        assert r.cpu_logical == 8
        assert r.total_ram_gb == 32.0
        assert r.available_ram_gb == 16.0
        assert r.platform != ""
        assert r.architecture != ""

    @patch("psutil.cpu_count")
    @patch("psutil.virtual_memory")
    def test_with_psutil_minimum(self, mock_vmem: MagicMock, mock_cpu: MagicMock) -> None:
        mock_cpu.side_effect = lambda logical=True: 1 if logical else 1
        mock_vmem.return_value.total = 512 * 1024**2
        mock_vmem.return_value.available = 256 * 1024**2
        opt = PerformanceOptimizer()
        r = opt.resources
        assert r.cpu_cores == 1 or r.cpu_logical == 1

    @patch("siyarix.performance.os.cpu_count", return_value=4)
    def test_without_psutil(self, mock_cpu: MagicMock) -> None:
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__
        with patch("builtins.__import__") as mock_import:
            def _side(name, *args, **kwargs):
                if name == "psutil":
                    raise ImportError("No psutil")
                return real_import(name, *args, **kwargs)
            mock_import.side_effect = _side
            opt = PerformanceOptimizer()
            r = opt.resources
            assert r.cpu_cores == 4
            assert r.cpu_logical == 4
            assert r.total_ram_gb == 8.0
            assert r.available_ram_gb == 4.0


class TestPerformanceOptimizerProperties:
    def setup_method(self) -> None:
        self.opt = PerformanceOptimizer()

    def test_resources_property(self) -> None:
        assert isinstance(self.opt.resources, SystemResources)

    def test_config_property(self) -> None:
        assert isinstance(self.opt.config, PerformanceConfig)


class TestPerformanceOptimizerAutoTune:
    def setup_method(self) -> None:
        self.opt = PerformanceOptimizer()
        # Override resources with known values
        self.opt._resources = SystemResources(
            cpu_cores=4,
            cpu_logical=8,
            total_ram_gb=32.0,
            available_ram_gb=16.0,
            platform="Linux",
            architecture="x86_64",
        )

    def test_auto_tune_sets_config(self) -> None:
        cfg = self.opt.auto_tune()
        assert cfg.max_concurrent_agents == self.opt._resources.recommended_max_agents
        assert cfg.memory_limit_per_agent_mb == self.opt._resources.recommended_memory_per_agent_mb
        assert cfg.enable_parallel_scanning is True
        assert cfg.enable_caching is True

    def test_auto_tune_low_cpu_disables_parallel(self) -> None:
        self.opt._resources = SystemResources(cpu_logical=2)
        cfg = self.opt.auto_tune()
        assert cfg.enable_parallel_scanning is False

    def test_auto_tune_returns_config(self) -> None:
        cfg = self.opt.auto_tune()
        assert isinstance(cfg, PerformanceConfig)


class TestPerformanceOptimizerConfigure:
    def setup_method(self) -> None:
        self.opt = PerformanceOptimizer()

    def test_set_valid_int(self) -> None:
        self.opt.configure(max_concurrent_agents=8)
        assert self.opt._config.max_concurrent_agents == 8

    def test_set_valid_string(self) -> None:
        self.opt.configure(log_level="DEBUG")
        assert self.opt._config.log_level == "DEBUG"

    def test_negative_int_rejected(self) -> None:
        self.opt.configure(max_concurrent_agents=-1)
        assert self.opt._config.max_concurrent_agents == 15  # unchanged

    def test_non_int_for_int_field_rejected(self) -> None:
        self.opt.configure(max_concurrent_agents="lots")
        assert self.opt._config.max_concurrent_agents == 15  # unchanged

    def test_unknown_key_ignored(self) -> None:
        self.opt.configure(nonexistent="value")
        # should not raise

    def test_returns_config(self) -> None:
        cfg = self.opt.configure(max_concurrent_agents=3)
        assert isinstance(cfg, PerformanceConfig)

    def test_network_bandwidth_negative_rejected(self) -> None:
        self.opt.configure(network_bandwidth_limit_mbps=-5)
        assert self.opt._config.network_bandwidth_limit_mbps == 0

    def test_memory_limit_negative_rejected(self) -> None:
        self.opt.configure(memory_limit_per_agent_mb=-100)
        assert self.opt._config.memory_limit_per_agent_mb == 2048  # unchanged

    def test_network_throttling_bool(self) -> None:
        self.opt.configure(network_throttling=True)
        assert self.opt._config.network_throttling is True

    def test_cpu_affinity_string(self) -> None:
        self.opt.configure(cpu_affinity="0-3")
        assert self.opt._config.cpu_affinity == "0-3"

    def test_enable_caching_false(self) -> None:
        self.opt.configure(enable_caching=False)
        assert self.opt._config.enable_caching is False


class TestPerformanceOptimizerRefreshResources:
    def test_returns_new_resources(self) -> None:
        opt = PerformanceOptimizer()
        r1 = opt.resources
        r2 = opt.refresh_resources()
        assert isinstance(r2, SystemResources)

    def test_updates_internal_resources(self) -> None:
        opt = PerformanceOptimizer()
        old = opt._resources
        new = opt.refresh_resources()
        assert opt._resources is new


class TestPerformanceOptimizerSummary:
    def setup_method(self) -> None:
        self.opt = PerformanceOptimizer()
        self.opt._resources = SystemResources(
            cpu_cores=4,
            cpu_logical=8,
            total_ram_gb=32.0,
            available_ram_gb=16.0,
            platform="Linux",
            architecture="x86_64",
        )

    def test_summary_keys(self) -> None:
        s = self.opt.summary()
        assert "resources" in s
        assert "config" in s
        assert "recommended" in s

    def test_summary_resources_values(self) -> None:
        s = self.opt.summary()
        res = s["resources"]
        assert res["cpu_cores"] == 4
        assert res["cpu_logical"] == 8
        assert res["ram_gb"] == 32.0
        assert res["ram_available_gb"] == 16.0

    def test_summary_recommended_values(self) -> None:
        s = self.opt.summary()
        rec = s["recommended"]
        assert rec["max_agents"] == 16  # min(8*2, 32//2, 64)
        assert rec["memory_per_agent_mb"] == 2048
        assert rec["concurrent_tools"] == 4


# ── Module-level singleton ───────────────────────────────────────────────

class TestPerformanceSingleton:
    def test_singleton_exists(self) -> None:
        assert isinstance(performance_optimizer, PerformanceOptimizer)

    def test_singleton_is_configured(self) -> None:
        assert isinstance(performance_optimizer.config, PerformanceConfig)


# ── Edge cases ───────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_resources_zero_ram(self) -> None:
        sr = SystemResources(cpu_logical=4, total_ram_gb=0.0)
        assert sr.recommended_max_agents == 1
        assert sr.recommended_memory_per_agent_mb == 256

    def test_resources_high_ram(self) -> None:
        sr = SystemResources(cpu_logical=32, total_ram_gb=256.0)
        assert sr.recommended_max_agents == 64  # capped
        assert sr.recommended_memory_per_agent_mb == 4096

    def test_auto_tune_before_summary(self) -> None:
        opt = PerformanceOptimizer()
        opt.auto_tune()
        s = opt.summary()
        assert s["config"]["max_concurrent_agents"] > 0

    def test_configure_updates_summary(self) -> None:
        opt = PerformanceOptimizer()
        opt.configure(max_concurrent_agents=3)
        s = opt.summary()
        assert s["config"]["max_concurrent_agents"] == 3
