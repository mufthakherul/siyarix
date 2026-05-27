from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from siyarix.ux.wizard import OnboardingWizard


@pytest.fixture
def wizard() -> OnboardingWizard:
    with patch("siyarix.ux.wizard.ToolRegistry") as mock_reg_cls:
        reg = MagicMock()
        reg.discover.return_value = []
        mock_reg_cls.return_value = reg
        yield OnboardingWizard()


class TestOnboardingWizard:
    def test_init(self, wizard: OnboardingWizard) -> None:
        assert isinstance(wizard.console, Console)
        assert wizard.registry is not None

    def test_run_complete(self, wizard: OnboardingWizard) -> None:
        with (
            patch.object(wizard, "_step_welcome", return_value=True),
            patch.object(wizard, "_step_model_provider"),
            patch.object(wizard, "_step_tool_discovery"),
            patch.object(wizard, "_step_theme_selector"),
            patch.object(wizard, "_step_mission_runner"),
            patch.object(wizard.console, "print"),
            patch.object(wizard.console, "clear"),
        ):
            result = wizard.run()
            assert result is True

    def test_run_welcome_fails(self, wizard: OnboardingWizard) -> None:
        with (
            patch.object(wizard, "_step_welcome", return_value=False),
            patch.object(wizard.console, "print"),
            patch.object(wizard.console, "clear"),
        ):
            result = wizard.run()
            assert result is False

    def test_step_welcome_accept(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Confirm.ask", return_value=True),
            patch.object(wizard.console, "print"),
            patch.object(wizard.console, "clear"),
        ):
            result = wizard._step_welcome()
            assert result is True

    def test_step_welcome_decline(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Confirm.ask", return_value=False),
            patch.object(wizard.console, "print"),
            patch.object(wizard.console, "clear"),
        ):
            result = wizard._step_welcome()
            assert result is False

    def test_step_model_provider_ollama(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Prompt.ask", return_value="1"),
            patch.object(wizard.console, "print"),
        ):
            wizard._step_model_provider()
            assert os.environ.get("SIYARIX_PROVIDER") == "ollama"

    def test_step_model_provider_gemini_no_key(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Prompt.ask", return_value="2"),
            patch.object(wizard.console, "print"),
        ):
            wizard._step_model_provider()
            assert os.environ.get("SIYARIX_PROVIDER") == "gemini"

    def test_step_model_provider_gemini_with_key(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Prompt.ask", side_effect=["2", "my-gemini-key"]),
            patch.object(wizard.console, "print"),
        ):
            wizard._step_model_provider()
            assert os.environ.get("GEMINI_API_KEY") == "my-gemini-key"
            assert os.environ.get("SIYARIX_PROVIDER") == "gemini"

    def test_step_model_provider_openai_no_key(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Prompt.ask", return_value="3"),
            patch.object(wizard.console, "print"),
        ):
            wizard._step_model_provider()
            assert os.environ.get("SIYARIX_PROVIDER") == "openai"

    def test_step_model_provider_openai_with_key(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Prompt.ask", side_effect=["3", "sk-my-key"]),
            patch.object(wizard.console, "print"),
        ):
            wizard._step_model_provider()
            assert os.environ.get("OPENAI_API_KEY") == "sk-my-key"

    def test_step_tool_discovery_with_tools(self, wizard: OnboardingWizard) -> None:
        tool1 = MagicMock()
        tool1.binary = "nmap"
        tool1.capabilities = ["port_scan"]
        tool1.category = "recon"
        tool2 = MagicMock()
        tool2.binary = "nuclei"
        tool2.capabilities = ["vuln_scan"]
        tool2.category = "web"

        wizard.registry.discover.return_value = [tool1, tool2]
        with (
            patch("siyarix.ux.wizard.time.sleep"),
            patch.object(wizard.console, "print"),
            patch.object(wizard.console, "status") as mock_status,
        ):
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cm)
            cm.__exit__ = MagicMock()
            mock_status.return_value = cm
            wizard._step_tool_discovery()
            wizard.registry.discover.assert_called_once_with(force_refresh=True, fast=True)

    def test_step_tool_discovery_empty(self, wizard: OnboardingWizard) -> None:
        wizard.registry.discover.return_value = []
        with (
            patch("siyarix.ux.wizard.time.sleep"),
            patch.object(wizard.console, "print"),
            patch.object(wizard.console, "status") as mock_status,
        ):
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cm)
            cm.__exit__ = MagicMock()
            mock_status.return_value = cm
            wizard._step_tool_discovery()

    def test_step_theme_selector(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Prompt.ask", return_value="neon"),
            patch.object(wizard.console, "print"),
            patch("siyarix.config.SettingsStore") as mock_store_cls,
        ):
            store = MagicMock()
            mock_store_cls.return_value = store
            wizard._step_theme_selector()
            store.set.assert_called_once_with("color_theme", "neon")

    def test_step_theme_selector_exception(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Prompt.ask", return_value="neon"),
            patch.object(wizard.console, "print"),
            patch("siyarix.config.SettingsStore", side_effect=Exception("fail")),
            patch("siyarix.ux.wizard.logger") as mock_log,
        ):
            wizard._step_theme_selector()
            mock_log.debug.assert_called_once()

    def test_step_mission_runner_confirm(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Confirm.ask", return_value=True),
            patch("siyarix.ux.wizard.time.sleep"),
            patch.object(wizard.console, "print"),
            patch.object(wizard.console, "status") as mock_status,
        ):
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cm)
            cm.__exit__ = MagicMock()
            mock_status.return_value = cm
            wizard._step_mission_runner()

    def test_step_mission_runner_skip(self, wizard: OnboardingWizard) -> None:
        with (
            patch("siyarix.ux.wizard.Confirm.ask", return_value=False),
            patch.object(wizard.console, "print"),
        ):
            wizard._step_mission_runner()

    def test_step_model_provider_choices(self, wizard: OnboardingWizard) -> None:
        with patch.object(wizard.console, "print"):
            for choice in ["1", "2", "3"]:
                with patch("siyarix.ux.wizard.Prompt.ask", return_value=choice):
                    wizard._step_model_provider()
