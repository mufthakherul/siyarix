"""Tests for ToolInstaller."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from siyarix.tool_installer import ToolInstaller, ToolInstallResult


class TestToolInstaller:
    @pytest.fixture
    def installer(self):
        return ToolInstaller()

    def test_init(self, installer):
        assert installer._install_history == []

    def test_is_installed_known(self, installer):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            assert installer.is_installed("nmap") is True

    def test_is_installed_unknown(self, installer):
        with patch("shutil.which", return_value=None):
            assert installer.is_installed("nonexistent-tool") is False

    def test_check_many(self, installer):
        def fake_which(cmd):
            return "/usr/bin/" + cmd if cmd in ("nmap", "curl") else None

        with patch("shutil.which", side_effect=fake_which):
            results = installer.check_many(["nmap", "curl", "nonexistent"])
            assert results["nmap"] is True
            assert results["curl"] is True
            assert results["nonexistent"] is False

    def test_install_already_present(self, installer):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = installer.install("nmap")
            assert result.success is True
            assert result.method == "already_installed"

    def test_install_unknown_tool(self, installer):
        with patch("shutil.which", return_value=None):
            result = installer.install("completely-unknown-tool-xyz")
            assert result.success is False
            assert "No install method known" in result.error

    def test_install_history(self, installer):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            installer.install("nmap")
            assert len(installer.history) == 1

    def test_install_history_reset(self, installer):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            installer.install("nmap")
            installer.reset()
            assert len(installer.history) == 0

    def test_install_result_dataclass(self):
        result = ToolInstallResult(tool="test", success=True, method="pip", output="ok")
        assert result.tool == "test"
        assert result.success is True

    def test_auto_install_missing(self, installer):
        with patch.object(installer, "is_installed", return_value=False):
            with patch.object(
                installer, "install", return_value=ToolInstallResult(tool="nmap", success=False)
            ):
                results = installer.auto_install_missing(["nmap"])
                assert len(results) == 1
