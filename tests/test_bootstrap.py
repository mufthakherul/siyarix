"""Tests for BootstrapEngine."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest
from siyarix.bootstrap import BootstrapEngine, BootstrapResult, PlatformInfo, SIYARIX_HOME
pytestmark = pytest.mark.bootstrap


class TestBootstrapEngine:
    def test_initialization(self):
        engine = BootstrapEngine()
        assert engine._home == SIYARIX_HOME

    def test_detect_platform(self):
        engine = BootstrapEngine()
        info = engine.detect_platform()
        assert isinstance(info, PlatformInfo)
        assert info.system == platform.system()
        assert info.python_version

    def test_check_python_version(self):
        engine = BootstrapEngine()
        assert engine.check_python_version() is True

    def test_check_dependencies(self):
        engine = BootstrapEngine()
        deps = engine.check_dependencies()
        assert "pydantic" in deps

    def test_ensure_directory_structure(self, tmp_path: Path):
        engine = BootstrapEngine(siyarix_home=tmp_path)
        engine.ensure_directory_structure()
        assert (tmp_path / "personas").exists()
        assert (tmp_path / "plugins" / "installed").exists()
        assert (tmp_path / "memory").exists()
        assert (tmp_path / "logs" / "sessions").exists()
        assert (tmp_path / "vault").exists()
        assert (tmp_path / "cache" / "tool_outputs").exists()
        assert (tmp_path / "templates" / "reports").exists()
        assert (tmp_path / "masking").exists()

    def test_first_run_detection(self, tmp_path: Path):
        marker = tmp_path / ".initialized"
        engine = BootstrapEngine(siyarix_home=tmp_path)
        assert engine.is_first_run is True
        marker.write_text("initialized")
        assert engine.is_first_run is False

    @pytest.mark.asyncio
    async def test_run_skip_if_initialized(self, tmp_path: Path):
        marker = tmp_path.parent / ".initialized"
        marker.write_text("initialized")
        engine = BootstrapEngine(siyarix_home=tmp_path)
        result = await engine.run()
        assert result.success is True

    def test_bootstrap_result_defaults(self):
        result = BootstrapResult()
        assert result.success is False
        assert result.first_run is False
        assert isinstance(result.platform, PlatformInfo)

    def test_platform_info_defaults(self):
        info = PlatformInfo()
        assert info.system == ""
