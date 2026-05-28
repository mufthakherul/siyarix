# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest.mock import MagicMock, patch

import pytest

from siyarix.performance import (
    PerformanceConfig,
    PerformanceOptimizer,
    SystemResources,
    performance_optimizer,
)


@pytest.fixture
def optimizer():
    return PerformanceOptimizer()


@pytest.fixture
def mock_psutil():
    mock = MagicMock()
    mock.cpu_count.side_effect = lambda logical: 8 if logical else 4
    mock.virtual_memory.return_value.total = 16 * (1024 ** 3)
    mock.virtual_memory.return_value.available = 8 * (1024 ** 3)
    return mock


class TestSystemResources:
    def test_recommended_max_agents(self):
        sr = SystemResources(cpu_logical=8, total_ram_gb=16.0)
        assert sr.recommended_max_agents == 8

    def test_recommended_max_agents_capped(self):
        sr = SystemResources(cpu_logical=128, total_ram_gb=512.0)
        assert sr.recommended_max_agents == 64

    def test_recommended_max_agents_min(self):
        sr = SystemResources(cpu_logical=1, total_ram_gb=1.0)
        assert sr.recommended_max_agents == 1

    def test_recommended_memory_per_agent_64gb(self):
        sr = SystemResources(total_ram_gb=64.0)
        assert sr.recommended_memory_per_agent_mb == 4096

    def test_recommended_memory_per_agent_32gb(self):
        sr = SystemResources(total_ram_gb=32.0)
        assert sr.recommended_memory_per_agent_mb == 2048

    def test_recommended_memory_per_agent_16gb(self):
        sr = SystemResources(total_ram_gb=16.0)
        assert sr.recommended_memory_per_agent_mb == 1024

    def test_recommended_memory_per_agent_8gb(self):
        sr = SystemResources(total_ram_gb=8.0)
        assert sr.recommended_memory_per_agent_mb == 512

    def test_recommended_memory_per_agent_4gb(self):
        sr = SystemResources(total_ram_gb=4.0)
        assert sr.recommended_memory_per_agent_mb == 256

    def test_recommended_concurrent_tools(self):
        sr = SystemResources(cpu_logical=8)
        assert sr.recommended_concurrent_tools == 4

    def test_recommended_concurrent_tools_min_one(self):
        sr = SystemResources(cpu_logical=1)
        assert sr.recommended_concurrent_tools == 1


class TestPerformanceOptimizer:
    def test_init(self, optimizer):
        assert isinstance(optimizer._config, PerformanceConfig)
        assert isinstance(optimizer._resources, SystemResources)
        assert optimizer._resources.platform != ""

    def test_resources_property(self, optimizer):
        assert optimizer.resources.cpu_cores > 0

    def test_config_property(self, optimizer):
        assert optimizer.config.max_concurrent_agents == 15

    def test_auto_tune(self, optimizer):
        result = optimizer.auto_tune()
        assert isinstance(result, PerformanceConfig)
        assert result.max_concurrent_agents > 0

    def test_configure_valid(self, optimizer):
        result = optimizer.configure(max_concurrent_agents=10, memory_limit_per_agent_mb=1024, cpu_affinity="manual")
        assert result.max_concurrent_agents == 10
        assert result.memory_limit_per_agent_mb == 1024
        assert result.cpu_affinity == "manual"

    def test_configure_invalid_key(self, optimizer):
        result = optimizer.configure(nonexistent_key=42)
        assert result.max_concurrent_agents == 15

    def test_configure_negative_value(self, optimizer):
        result = optimizer.configure(max_concurrent_agents=-5)
        assert result.max_concurrent_agents == 15

    def test_configure_non_int_value(self, optimizer):
        result = optimizer.configure(max_concurrent_agents="abc")
        assert result.max_concurrent_agents == 15

    def test_configure_bool_value(self, optimizer):
        result = optimizer.configure(enable_parallel_scanning=False, enable_caching=False)
        assert result.enable_parallel_scanning is False
        assert result.enable_caching is False

    def test_configure_network_throttling(self, optimizer):
        result = optimizer.configure(network_throttling=True, network_bandwidth_limit_mbps=100)
        assert result.network_throttling is True
        assert result.network_bandwidth_limit_mbps == 100

    def test_refresh_resources(self, optimizer):
        resources = optimizer.refresh_resources()
        assert isinstance(resources, SystemResources)

    def test_summary(self, optimizer):
        summary = optimizer.summary()
        assert "resources" in summary
        assert "config" in summary
        assert "recommended" in summary
        assert summary["recommended"]["max_agents"] > 0

    def test_detect_resources_with_psutil(self, optimizer, mock_psutil):
        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            sr = optimizer._detect_resources()
            assert sr.cpu_logical == 8
            assert sr.cpu_cores == 4
            assert sr.total_ram_gb == 16.0
            assert sr.available_ram_gb == 8.0

    def test_detect_resources_without_psutil(self, optimizer):
        with patch.dict("sys.modules", {"psutil": None}):
            sr = optimizer._detect_resources()
            assert sr.cpu_logical >= 1
            assert sr.total_ram_gb == 8.0
            assert sr.available_ram_gb == 4.0

    def test_module_singleton(self):
        assert performance_optimizer is not None
        assert isinstance(performance_optimizer, PerformanceOptimizer)
