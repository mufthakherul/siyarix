# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.health — system health checks."""

from __future__ import annotations

import os
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.health import (
    ComponentHealth,
    HealthChecker,
    HealthState,
    HealthStatus,
    get_health,
)


class TestHealthState:
    def test_values(self) -> None:
        assert HealthState.HEALTHY == "healthy"
        assert HealthState.DEGRADED == "degraded"
        assert HealthState.UNHEALTHY == "unhealthy"


class TestComponentHealth:
    def test_defaults(self) -> None:
        c = ComponentHealth(name="test", state=HealthState.HEALTHY)
        assert c.message == ""
        assert c.latency_ms == 0.0
        assert c.details == {}
        assert isinstance(c.timestamp, datetime)


class TestHealthStatus:
    def test_is_healthy_true(self) -> None:
        s = HealthStatus(state=HealthState.HEALTHY)
        assert s.is_healthy is True
        assert s.is_degraded is False

    def test_is_healthy_false(self) -> None:
        s = HealthStatus(state=HealthState.UNHEALTHY)
        assert s.is_healthy is False

    def test_is_degraded(self) -> None:
        s = HealthStatus(state=HealthState.DEGRADED)
        assert s.is_degraded is True
        assert s.is_healthy is False

    def test_to_dict(self) -> None:
        s = HealthStatus(
            state=HealthState.HEALTHY,
            components=[ComponentHealth(name="CPU", state=HealthState.HEALTHY, message="OK")],
            checks_performed=1,
            uptime_seconds=100.0,
        )
        d = s.to_dict()
        assert d["state"] == "healthy"
        assert d["is_healthy"] is True
        assert d["uptime_seconds"] == 100.0
        assert d["checks_performed"] == 1
        assert len(d["components"]) == 1
        assert d["components"][0]["name"] == "CPU"


class TestHealthChecker:
    @pytest.fixture(autouse=True)
    def mock_home(self, tmp_path):
        with patch("pathlib.Path.home", return_value=tmp_path):
            yield

    @pytest.fixture
    def checker(self) -> HealthChecker:
        c = HealthChecker()
        HealthChecker._instance = None
        return c

    @pytest.fixture
    def checker_with_mocks(self) -> HealthChecker:
        c = HealthChecker()
        c._check_model_providers = AsyncMock()
        c._check_tool_registry = AsyncMock()
        c._check_system_resources = AsyncMock()
        return c

    def test_singleton(self) -> None:
        HealthChecker._instance = None
        c1 = HealthChecker.instance()
        c2 = HealthChecker.instance()
        assert c1 is c2

    def test_instance_creates_new(self) -> None:
        HealthChecker._instance = None
        c = HealthChecker.instance()
        assert c is not None

    @pytest.mark.asyncio
    async def test_check_all_healthy(self, checker_with_mocks: HealthChecker) -> None:
        status = await checker_with_mocks.check_all()
        assert status.state == HealthState.HEALTHY
        assert status.checks_performed == 0
        assert status.uptime_seconds >= 0

    @pytest.mark.asyncio
    async def test_check_all_unhealthy(self, checker_with_mocks: HealthChecker) -> None:
        async def add_unhealthy(status: HealthStatus) -> None:
            status.components.append(ComponentHealth(name="Test", state=HealthState.UNHEALTHY))

        async def add_degraded(status: HealthStatus) -> None:
            status.components.append(ComponentHealth(name="Test2", state=HealthState.DEGRADED))

        checker_with_mocks._check_system_resources = add_unhealthy  # type: ignore
        checker_with_mocks._check_tool_registry = add_degraded  # type: ignore
        status = await checker_with_mocks.check_all()
        assert status.state == HealthState.UNHEALTHY

    @pytest.mark.asyncio
    async def test_check_all_degraded(self, checker_with_mocks: HealthChecker) -> None:
        async def add_degraded(status: HealthStatus) -> None:
            status.components.append(ComponentHealth(name="Test", state=HealthState.DEGRADED))

        checker_with_mocks._check_system_resources = add_degraded  # type: ignore
        status = await checker_with_mocks.check_all()
        assert status.state == HealthState.DEGRADED

    # ── Model Providers ────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_check_model_providers_openai_configured(self, checker: HealthChecker) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            openai_comp = [c for c in status.components if c.name == "ModelProvider/OpenAI"][0]
            assert openai_comp.state == HealthState.HEALTHY

    @pytest.mark.asyncio
    async def test_check_model_providers_openai_not_configured(
        self, checker: HealthChecker
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            openai_comp = [c for c in status.components if c.name == "ModelProvider/OpenAI"][0]
            assert openai_comp.state == HealthState.DEGRADED

    @pytest.mark.asyncio
    async def test_check_model_providers_gemini_configured(self, checker: HealthChecker) -> None:
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=True):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            gemini_comp = [c for c in status.components if "Gemini" in c.name][0]
            assert gemini_comp.state == HealthState.HEALTHY

    @pytest.mark.asyncio
    async def test_check_model_providers_gemini_google_key(self, checker: HealthChecker) -> None:
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}, clear=True):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            gemini_comp = [c for c in status.components if "Gemini" in c.name][0]
            assert gemini_comp.state == HealthState.HEALTHY

    @pytest.mark.asyncio
    async def test_check_model_providers_ollama_running(self, checker: HealthChecker) -> None:
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_client.__aenter__.return_value.get.return_value = mock_response
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            ollama_comp = [c for c in status.components if "Ollama" in c.name][0]
            assert ollama_comp.state == HealthState.HEALTHY

    @pytest.mark.asyncio
    async def test_check_model_providers_ollama_not_running(self, checker: HealthChecker) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get.side_effect = Exception("Connection refused")
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            ollama_comp = [c for c in status.components if "Ollama" in c.name][0]
            assert ollama_comp.state == HealthState.DEGRADED

    @pytest.mark.asyncio
    async def test_check_model_providers_cloud_configured(self, checker: HealthChecker) -> None:
        with patch.dict(
            os.environ,
            {"SIYARIX_SERVER_URL": "https://siyarix.cloud", "SIYARIX_API_KEY": "key"},
            clear=True,
        ):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            cloud_comp = [c for c in status.components if "Cloud" in c.name][0]
            assert cloud_comp.state == HealthState.HEALTHY

    @pytest.mark.asyncio
    async def test_check_model_providers_exception(self, checker: HealthChecker) -> None:
        with patch.dict(os.environ, {}, clear=True):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_model_providers(status)
            assert len(status.components) == 27

    # ── Tool Registry ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_check_tool_registry_all_found(self, checker: HealthChecker) -> None:
        with patch("shutil.which", return_value="/usr/bin/bash"):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_tool_registry(status)
            registry_comp = [c for c in status.components if c.name == "ToolRegistry"][0]
            assert registry_comp.state == HealthState.HEALTHY
            assert "4/4" in registry_comp.message

    @pytest.mark.asyncio
    async def test_check_tool_registry_partial(self, checker: HealthChecker) -> None:
        import os

        partial_tool = "python.exe" if os.name == "nt" else "bash"

        def which_side(tool: str) -> str | None:
            return f"/usr/bin/{partial_tool}" if tool == partial_tool else None

        with patch("shutil.which", side_effect=which_side):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_tool_registry(status)
            registry_comp = [c for c in status.components if c.name == "ToolRegistry"][0]
            assert registry_comp.state == HealthState.DEGRADED

    @pytest.mark.asyncio
    async def test_check_tool_registry_none_found(self, checker: HealthChecker) -> None:
        with patch("shutil.which", return_value=None):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_tool_registry(status)
            registry_comp = [c for c in status.components if c.name == "ToolRegistry"][0]
            assert registry_comp.state == HealthState.UNHEALTHY

    @pytest.mark.asyncio
    async def test_check_tool_registry_exception(self, checker: HealthChecker) -> None:
        with patch("shutil.which", side_effect=Exception("broken")):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_tool_registry(status)
            tool_comps = [c for c in status.components if c.name.startswith("Tool/")]
            assert all(c.state == HealthState.UNHEALTHY for c in tool_comps)
            registry_comp = [c for c in status.components if c.name == "ToolRegistry"][0]
            assert registry_comp.state == HealthState.UNHEALTHY

    # ── System Resources ───────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_check_system_resources_healthy(self, checker: HealthChecker) -> None:
        mock_memory = MagicMock()
        mock_memory.percent = 50.0
        mock_memory.used = 8 * 1024**3
        mock_memory.total = 16 * 1024**3
        mock_disk = MagicMock()
        mock_disk.percent = 60.0
        mock_disk.used = 100 * 1024**3
        mock_disk.total = 200 * 1024**3
        with (
            patch("psutil.virtual_memory", return_value=mock_memory),
            patch("psutil.disk_usage", return_value=mock_disk),
            patch("psutil.cpu_percent", return_value=50.0),
        ):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_system_resources(status)
            assert len(status.components) == 3

    @pytest.mark.asyncio
    async def test_check_system_resources_degraded_memory(self, checker: HealthChecker) -> None:
        mock_memory = MagicMock()
        mock_memory.percent = 85.0
        mock_memory.used = 13 * 1024**3
        mock_memory.total = 16 * 1024**3
        mock_disk = MagicMock()
        mock_disk.percent = 50.0
        mock_disk.used = 100 * 1024**3
        mock_disk.total = 200 * 1024**3
        with (
            patch("psutil.virtual_memory", return_value=mock_memory),
            patch("psutil.disk_usage", return_value=mock_disk),
            patch("psutil.cpu_percent", return_value=50.0),
        ):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_system_resources(status)
            mem_comp = [c for c in status.components if c.name == "SystemMemory"][0]
            assert mem_comp.state == HealthState.DEGRADED

    @pytest.mark.asyncio
    async def test_check_system_resources_unhealthy_memory(self, checker: HealthChecker) -> None:
        mock_memory = MagicMock()
        mock_memory.percent = 96.0
        mock_memory.used = 15 * 1024**3
        mock_memory.total = 16 * 1024**3
        mock_disk = MagicMock()
        mock_disk.percent = 50.0
        mock_disk.used = 100 * 1024**3
        mock_disk.total = 200 * 1024**3
        with (
            patch("psutil.virtual_memory", return_value=mock_memory),
            patch("psutil.disk_usage", return_value=mock_disk),
            patch("psutil.cpu_percent", return_value=50.0),
        ):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_system_resources(status)
            mem_comp = [c for c in status.components if c.name == "SystemMemory"][0]
            assert mem_comp.state == HealthState.UNHEALTHY

    @pytest.mark.asyncio
    async def test_check_system_resources_no_psutil(self, checker: HealthChecker) -> None:
        old_import = (
            __builtins__["__import__"]
            if isinstance(__builtins__, dict)
            else __builtins__.__import__
        )  # type: ignore[union-attr]

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "psutil":
                raise ImportError("no psutil")
            return old_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            status = HealthStatus(state=HealthState.HEALTHY)
            await checker._check_system_resources(status)
            assert len(status.components) == 0


def test_get_health() -> None:
    HealthChecker._instance = None
    h = get_health()
    assert isinstance(h, HealthChecker)
