# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for tool installation, uninstallation, modification, and management."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from siyarix.cli import app
from siyarix.exceptions import PermissionDeniedError
from siyarix.registry import ToolRegistry
from siyarix.tool_config import CustomToolDefinition, ToolConfigManager
from siyarix.tool_installer import ToolInstaller
from siyarix.tool_models import RiskLevel, ToolCategory

runner = CliRunner()


# ── ToolConfigManager Tests ──────────────────────────────────────────────────


def test_tool_config_manager_overrides(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)

    # Set override
    override = mgr.set_override(
        "nmap",
        binary_path="/opt/custom/nmap",
        risk_level="safe",
        default_args=["-Pn", "--rate", "1000"],
        timeout=60,
    )
    assert override.binary_path == "/opt/custom/nmap"
    assert override.risk_level == "safe"
    assert override.default_args == ["-Pn", "--rate", "1000"]
    assert override.timeout == 60

    # Verify saved to disk
    assert config_file.exists()
    content = json.loads(config_file.read_text(encoding="utf-8"))
    assert "nmap" in content["overrides"]
    assert content["overrides"]["nmap"]["binary_path"] == "/opt/custom/nmap"

    # Reload from disk
    mgr2 = ToolConfigManager(config_file=config_file)
    reloaded = mgr2.get_override("nmap")
    assert reloaded is not None
    assert reloaded.binary_path == "/opt/custom/nmap"
    assert reloaded.timeout == 60

    # Remove override
    assert mgr.remove_override("nmap") is True
    assert mgr.get_override("nmap") is None
    assert mgr.remove_override("nonexistent") is False


def test_tool_config_manager_custom_tools(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)

    custom = CustomToolDefinition(
        name="my_scanner",
        binary="/usr/local/bin/my_scanner.sh",
        description="Internal corporate scanner",
        category="scanning",
        risk_level="low",
        default_args=["--fast"],
        timeout=90,
    )
    mgr.add_custom_tool(custom)

    retrieved = mgr.get_custom_tool("my_scanner")
    assert retrieved is not None
    assert retrieved.binary == "/usr/local/bin/my_scanner.sh"
    assert retrieved.category == "scanning"
    assert retrieved.default_args == ["--fast"]

    assert len(mgr.list_custom_tools()) == 1

    # Remove custom tool
    assert mgr.remove_custom_tool("my_scanner") is True
    assert mgr.get_custom_tool("my_scanner") is None
    assert len(mgr.list_custom_tools()) == 0


def test_tool_config_manager_enable_disable(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)

    # By default unknown tools are enabled
    assert mgr.is_tool_enabled("nikto") is True

    # Disable
    mgr.disable_tool("nikto")
    assert mgr.is_tool_enabled("nikto") is False

    # Enable
    mgr.enable_tool("nikto")
    assert mgr.is_tool_enabled("nikto") is True

    # Custom tool disable/enable
    custom = CustomToolDefinition(name="custom_exploit", binary="/bin/true")
    mgr.add_custom_tool(custom)
    assert mgr.is_tool_enabled("custom_exploit") is True

    mgr.disable_tool("custom_exploit")
    assert mgr.is_tool_enabled("custom_exploit") is False

    mgr.enable_tool("custom_exploit")
    assert mgr.is_tool_enabled("custom_exploit") is True


def test_tool_config_manager_reset(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)

    mgr.set_override("nmap", risk_level="safe")
    mgr.set_override("sqlmap", timeout=30)
    assert len(mgr.list_overrides()) == 2

    # Reset single tool
    mgr.reset("nmap")
    assert mgr.get_override("nmap") is None
    assert mgr.get_override("sqlmap") is not None

    # Reset all
    mgr.reset()
    assert len(mgr.list_overrides()) == 0


# ── ToolInstaller Tests ──────────────────────────────────────────────────────


def test_tool_installer_recipe_lookup():
    installer = ToolInstaller()
    recipe = installer.get_install_recipe("nmap")
    assert recipe["tool"] == "nmap"
    assert "package" in recipe
    assert "install_cmd" in recipe
    assert "uninstall_cmd" in recipe
    assert "all_recipes" in recipe
    assert "winget" in recipe["all_recipes"]
    assert "apt" in recipe["all_recipes"]


def test_tool_installer_uninstall_not_installed():
    installer = ToolInstaller()
    with patch.object(installer, "is_installed", return_value=False):
        res = installer.uninstall("some-absent-tool")
        assert res.success is True
        assert res.method == "not_installed"


def test_tool_installer_uninstall_custom_tool(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)
    with patch(
        "siyarix.tool_config.ToolConfigManager.get_instance",
        return_value=mgr,
    ):
        mgr.add_custom_tool(CustomToolDefinition(name="my_tool", binary="/bin/true"))
        assert mgr.get_custom_tool("my_tool") is not None

        installer = ToolInstaller()
        with patch.object(installer, "is_installed", return_value=True):
            res = installer.uninstall("my_tool")
            assert res.success is True
            assert mgr.get_custom_tool("my_tool") is None


def test_tool_installer_uninstall_system_tool_win():
    installer = ToolInstaller()
    with patch("os.name", "nt"):
        with patch.object(installer, "is_installed", return_value=True):
            with patch("shutil.which", return_value="/usr/bin/winget"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    res = installer.uninstall("nmap")
                    assert res.success is True
                    mock_run.assert_called_once()
                    cmd = mock_run.call_args[0][0]
                    assert "winget" in cmd
                    assert "uninstall" in cmd


def test_tool_installer_uninstall_system_tool_nix():
    installer = ToolInstaller()
    with patch("os.name", "posix"):
        with patch.object(installer, "is_installed", return_value=True):
            with patch.object(installer, "_detect_pm", return_value="apt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    res = installer.uninstall("nmap", purge=True)
                    assert res.success is True
                    mock_run.assert_called_once()
                    cmd = mock_run.call_args[0][0]
                    assert "apt-get" in cmd
                    assert "purge" in cmd


def test_tool_installer_update_tool():
    installer = ToolInstaller()
    with patch("os.name", "posix"):
        with patch.object(installer, "_detect_pm", return_value="pkg"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                res = installer.update("nmap")
                assert res.success is True
                cmd = mock_run.call_args[0][0]
                assert cmd == ["pkg", "upgrade", "-y", "nmap"]


# ── ToolRegistry Integration Tests ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_registry_blocks_disabled_tool(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)
    mgr.disable_tool("nmap")

    with patch(
        "siyarix.tool_config.ToolConfigManager.get_instance",
        return_value=mgr,
    ):
        reg = ToolRegistry()
        with patch("siyarix.registry._cached_which", return_value="/usr/bin/nmap"):
            reg.discover_from_path()
            tool = reg.graph.get_tool("nmap")
            assert tool is not None
            assert tool.enabled is False

            with pytest.raises(PermissionDeniedError, match="disabled"):
                await reg.execute("nmap", target="127.0.0.1")


@pytest.mark.asyncio
async def test_registry_registers_custom_tool(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)
    mgr.add_custom_tool(
        CustomToolDefinition(
            name="custom_echo",
            binary="/usr/bin/echo",
            description="Custom echo utility",
            category="utility",
            risk_level="safe",
            default_args=["--custom-flag"],
        )
    )

    with patch(
        "siyarix.tool_config.ToolConfigManager.get_instance",
        return_value=mgr,
    ):
        reg = ToolRegistry()
        reg.discover_from_path()
        tool = reg.graph.get_tool("custom_echo")
        assert tool is not None
        assert tool.custom is True
        assert tool.category == ToolCategory.UTILITY
        assert tool.risk_level == RiskLevel.SAFE
        assert tool.default_args == ["--custom-flag"]


# ── CLI Commands Tests ───────────────────────────────────────────────────────


def test_cli_tools_list():
    result = runner.invoke(app, ["tools", "list", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) > 0


def test_cli_tools_search():
    result = runner.invoke(app, ["tools", "search", "scanner", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)


def test_cli_tools_info():
    result = runner.invoke(app, ["tools", "info", "nmap"])
    assert result.exit_code == 0
    assert "nmap" in result.output
    assert "Install Command" in result.output


def test_cli_tools_install_dry_run():
    result = runner.invoke(app, ["tools", "install", "--dry-run", "nmap", "ffuf"])
    assert result.exit_code == 0
    assert "Dry Run" in result.output
    assert "nmap" in result.output
    assert "ffuf" in result.output


def test_cli_tools_uninstall_dry_run():
    result = runner.invoke(app, ["tools", "uninstall", "--dry-run", "nmap"])
    assert result.exit_code == 0
    assert "Dry Run" in result.output
    assert "nmap" in result.output


def test_cli_tools_modify_and_reset(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)

    with patch(
        "siyarix.tool_config.ToolConfigManager.get_instance",
        return_value=mgr,
    ):
        res = runner.invoke(
            app,
            [
                "tools",
                "modify",
                "nmap",
                "--binary",
                "/custom/nmap",
                "--risk",
                "safe",
                "--timeout",
                "45",
            ],
        )
        assert res.exit_code == 0
        override = mgr.get_override("nmap")
        assert override is not None
        assert override.binary_path == "/custom/nmap"
        assert override.risk_level == "safe"
        assert override.timeout == 45

        # Enable / Disable via CLI
        res_dis = runner.invoke(app, ["tools", "disable", "nmap"])
        assert res_dis.exit_code == 0
        assert mgr.is_tool_enabled("nmap") is False

        res_en = runner.invoke(app, ["tools", "enable", "nmap"])
        assert res_en.exit_code == 0
        assert mgr.is_tool_enabled("nmap") is True

        # Reset via CLI
        res_reset = runner.invoke(app, ["tools", "reset", "nmap", "--yes"])
        assert res_reset.exit_code == 0
        assert mgr.get_override("nmap") is None


def test_cli_tools_add_and_remove_custom(tmp_path):
    config_file = tmp_path / "tools.json"
    mgr = ToolConfigManager(config_file=config_file)

    with patch(
        "siyarix.tool_config.ToolConfigManager.get_instance",
        return_value=mgr,
    ):
        res_add = runner.invoke(
            app,
            [
                "tools",
                "add-custom",
                "test_exploit",
                "--binary",
                "/usr/bin/exploit.py",
                "--description",
                "My test exploit",
                "--category",
                "exploitation",
                "--risk",
                "critical",
            ],
        )
        assert res_add.exit_code == 0
        custom = mgr.get_custom_tool("test_exploit")
        assert custom is not None
        assert custom.category == "exploitation"
        assert custom.risk_level == "critical"

        # Remove custom
        res_rm = runner.invoke(app, ["tools", "remove-custom", "test_exploit"])
        assert res_rm.exit_code == 0
        assert mgr.get_custom_tool("test_exploit") is None


def test_cli_tools_check():
    result = runner.invoke(app, ["tools", "check", "nmap"])
    assert result.exit_code == 0
    assert "Tool Health & Verification" in result.output
    assert "nmap" in result.output


# ── REPL / Chat Handler Tests ────────────────────────────────────────────────


def test_chat_cmd_tools(tmp_path):
    from siyarix.chat import SiyarixChat

    chat = SiyarixChat()
    with patch("siyarix.chat.handlers.console.print") as mock_print:
        chat._cmd_tools("")
        mock_print.assert_called()

        # Tools info
        chat._cmd_tools("info nmap")
        mock_print.assert_called()

        # Tools enable/disable
        chat._cmd_tools("disable nmap")
        mock_print.assert_called()
        chat._cmd_tools("enable nmap")
        mock_print.assert_called()


def test_chat_cmd_install_uninstall():
    from siyarix.chat import SiyarixChat

    chat = SiyarixChat()
    with patch("siyarix.tool_installer.tty_confirm", return_value=True):
        with patch("siyarix.tool_installer.ToolInstaller.install") as mock_inst:
            chat._cmd_install("nmap")
            mock_inst.assert_called_once_with("nmap")

        with patch("siyarix.tool_installer.ToolInstaller.uninstall") as mock_uninst:
            chat._cmd_uninstall("nmap")
            mock_uninst.assert_called_once_with("nmap")
