# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for multi-platform onboarding improvements:
- Termux pkg native tool detection and installer
- Parrot OS, BlackArch, Athena OS, Kali Linux security distribution detection
- Python 3.11+ requirement verification
- Smart API key pre-fill upfront
- Express setup mode
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix._platform import (
    detect_package_manager_platform,
    detect_security_distro,
    is_athena_os,
    is_blackarch,
    is_parrot_os,
    is_termux,
)
from siyarix.chat.platform_utils import pip_install_args
from siyarix.onboarding import OnboardingWizard
from siyarix.tool_installer import ToolInstaller


def test_termux_detection():
    """Verify Termux detection via environment variable and file path."""
    with patch.dict("os.environ", {"TERMUX_VERSION": "0.118.0"}):
        assert is_termux() is True

    with patch.dict("os.environ", {}, clear=True):
        with patch("pathlib.Path.exists", return_value=True):
            assert is_termux() is True


def test_termux_tool_installer_no_sudo():
    """Verify ToolInstaller uses pkg without sudo in Termux."""
    installer = ToolInstaller()
    with patch("siyarix.tool_installer.shutil.which", side_effect=lambda x: x == "pkg"):
        assert installer._detect_pm() == "pkg"

    with patch.object(installer, "_detect_pm", return_value="pkg"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(return_value=0, returncode=0)
            with patch("shutil.which", side_effect=lambda x: x == "nmap"):
                result = installer._install_nix("nmap", "nmap")
                assert result is True
                mock_run.assert_called_once()
                cmd = mock_run.call_args[0][0]
                assert cmd == ["pkg", "install", "-y", "nmap"]
                assert "sudo" not in cmd


def test_termux_pkg_map():
    """Verify Termux specific package mappings (dig -> dnsutils, openssl -> openssl-tool)."""
    installer = ToolInstaller()
    with patch.object(installer, "_detect_pm", return_value="pkg"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            with patch("shutil.which", return_value=True):
                installer._install_nix("dig", "dig")
                cmd = mock_run.call_args[0][0]
                assert cmd == ["pkg", "install", "-y", "dnsutils"]


def test_security_distro_detection():
    """Verify Kali, Parrot OS, BlackArch, and Athena OS detection."""
    # Parrot OS
    with patch("siyarix._platform.is_linux", return_value=True):
        with patch(
            "pathlib.Path.read_text",
            return_value='NAME="Parrot Security"\nID=parrot\n',
        ):
            with patch("pathlib.Path.exists", return_value=True):
                assert is_parrot_os() is True
                distro = detect_security_distro()
                assert distro["is_security"] is True
                assert distro["name"] == "Parrot Security OS"
                assert distro["family"] == "debian"

    # BlackArch Linux
    with patch("siyarix._platform.is_linux", return_value=True):
        with patch("siyarix._platform.is_parrot_os", return_value=False):
            with patch("siyarix._platform.is_kali_linux", return_value=False):
                with patch(
                    "pathlib.Path.read_text",
                    return_value='NAME="BlackArch Linux"\nID=blackarch\n',
                ):
                    with patch("pathlib.Path.exists", return_value=True):
                        assert is_blackarch() is True
                        distro = detect_security_distro()
                        assert distro["is_security"] is True
                        assert distro["name"] == "BlackArch Linux"
                        assert distro["family"] == "arch"

    # Athena OS
    with patch("siyarix._platform.is_linux", return_value=True):
        with patch("siyarix._platform.is_parrot_os", return_value=False):
            with patch("siyarix._platform.is_kali_linux", return_value=False):
                with patch("siyarix._platform.is_blackarch", return_value=False):
                    with patch(
                        "pathlib.Path.read_text",
                        return_value='NAME="Athena OS"\nID=athena\n',
                    ):
                        with patch("pathlib.Path.exists", return_value=True):
                            assert is_athena_os() is True
                            distro = detect_security_distro()
                            assert distro["is_security"] is True
                            assert distro["name"] == "Athena OS"
                            assert distro["family"] == "arch"


def test_pip_install_args_security_distros():
    """Verify pip_install_args passes --break-system-packages on Kali and Parrot OS."""
    with patch("siyarix.chat.platform_utils.is_kali_linux", return_value=True):
        args = pip_install_args("requests")
        assert "--break-system-packages" in args

    with patch("siyarix.chat.platform_utils.is_kali_linux", return_value=False):
        with patch("siyarix.chat.platform_utils.is_parrot_os", return_value=True):
            args = pip_install_args("requests")
            assert "--break-system-packages" in args

    with patch("siyarix.chat.platform_utils.is_kali_linux", return_value=False):
        with patch("siyarix.chat.platform_utils.is_parrot_os", return_value=False):
            with patch(
                "siyarix.chat.platform_utils.detect_security_distro",
                return_value={"is_security": False},
            ):
                args = pip_install_args("requests")
                assert "--break-system-packages" not in args


def test_detect_package_manager_platform():
    """Verify package manager detection on Termux and Arch security distros."""
    with patch("siyarix._platform.is_termux", return_value=True):
        assert detect_package_manager_platform() == "pkg"

    with patch("siyarix._platform.is_termux", return_value=False):
        with patch("siyarix._platform.get_platform_id", return_value="linux"):
            with patch(
                "siyarix._platform.detect_security_distro",
                return_value={"is_security": True, "pm": "pacman"},
            ):
                with patch("shutil.which", side_effect=lambda x: x == "pacman"):
                    assert detect_package_manager_platform() == "pacman"


@pytest.mark.asyncio
async def test_requirements_allows_python_311(tmp_path):
    """Verify onboarding requirements check allows Python 3.11."""
    console = MagicMock()
    wizard = OnboardingWizard(console=console, non_interactive=True)
    with patch("siyarix.onboarding.get_config_dir", return_value=tmp_path):
        with patch("siyarix.onboarding.shutil.which", return_value="/usr/bin/tool"):
            with patch("sys.version_info", (3, 11, 8, "final", 0)):
                with patch("sys.exit") as mock_exit:
                    await wizard._step_requirements()
                    mock_exit.assert_not_called()


def test_smart_api_key_detection(tmp_path):
    """Verify detecting existing API keys from environment and .env upfront."""
    console = MagicMock()
    wizard = OnboardingWizard(console=console)
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-test123\n")

    with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test456"}):
        with patch("siyarix.onboarding.get_config_dir", return_value=tmp_path):
            keys = wizard._detect_existing_api_keys()
            assert keys.get("openai") == "sk-test456"
            assert keys.get("anthropic") == "sk-ant-test123"


@pytest.mark.asyncio
async def test_express_onboarding_run(tmp_path):
    """Verify express non-interactive onboarding completes smoothly without blocking."""
    console = MagicMock()
    settings = MagicMock()
    wizard = OnboardingWizard(
        settings=settings,
        console=console,
        express=True,
        non_interactive=True,
    )
    with patch.dict("os.environ", {"GEMINI_API_KEY": "AIzaSyTestKey"}):
        with patch("siyarix.onboarding.get_config_dir", return_value=tmp_path):
            with patch("siyarix.onboarding.shutil.which", return_value="/usr/bin/tool"):
                with patch("siyarix.onboarding.INITIALIZED_MARKER", tmp_path / ".initialized"):
                    with patch.object(wizard, "_step_network_diagnostics", new=AsyncMock()):
                        completed = await wizard.run()
                        assert completed is True
                        assert wizard._choices["ethics_accepted"] is True
                        assert wizard._choices["mode"] == "integrated"
                        assert wizard._choices["persona"] == "auto"
                        assert wizard._choices["provider_name"] == "gemini"
                        assert wizard._choices["provider_type"] == "online"
                        settings.set.assert_any_call("onboarding_complete", True)
                        assert (tmp_path / ".initialized").exists()
