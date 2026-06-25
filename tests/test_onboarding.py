import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from siyarix.onboarding import OnboardingWizard


@pytest.fixture(autouse=True)
def mock_rich_inputs():
    with (
        patch("siyarix.onboarding.Prompt.ask", return_value="1") as m_prompt,
        patch("siyarix.onboarding.Confirm.ask", return_value=True) as m_confirm,
        patch("siyarix.onboarding.Console") as m_console,
        patch("builtins.input", return_value=""),
    ):
        yield m_prompt, m_confirm, m_console


@pytest.fixture
def mock_console():
    return MagicMock()


@pytest.fixture
def mock_settings():
    settings = MagicMock()
    settings.save = MagicMock()
    return settings


@pytest.mark.asyncio
@patch("siyarix.onboarding.shutil.which")
@patch("siyarix.onboarding.subprocess.run")
@patch("siyarix.onboarding.get_config_dir")
async def test_onboarding_full_run(
    mock_get_config, mock_subproc, mock_which, mock_settings, mock_console, tmp_path
):
    mock_get_config.return_value = tmp_path
    mock_which.return_value = "/usr/bin/tool"
    mock_run_result = MagicMock()
    mock_run_result.returncode = 0
    mock_run_result.stdout = "mocked output"
    mock_subproc.return_value = mock_run_result

    with patch(
        "siyarix.onboarding.Prompt.ask", side_effect=["c", "5", "1", "a", "1", "1", "1", "1", "1"]
    ):
        with patch("siyarix.onboarding.Confirm.ask", return_value=True):
            with patch("siyarix.onboarding.BootstrapEngine") as mock_bootstrap:
                mock_bootstrap.return_value.setup_directories = MagicMock()
                mock_bootstrap.return_value.install_package = AsyncMock(return_value=True)
                with patch("siyarix.onboarding.ProviderManager") as mock_mgr:
                    mock_mgr.get_instance.return_value = MagicMock()
                    wizard = OnboardingWizard(settings=mock_settings, console=mock_console)
                    # Skeleton run
                    wizard._step_credential_setup = MagicMock()
                    wizard._step_provider = AsyncMock()
                    wizard._step_mode = MagicMock()
                    wizard._step_persona_sysmsg = MagicMock()
                    wizard._step_install_persona_tools = MagicMock()
                    wizard._step_preferences = MagicMock()
                    wizard._step_learning_setup = MagicMock()
                    wizard._step_network_diagnostics = AsyncMock()
                    wizard._finalize = AsyncMock()
                    result = await wizard.run()
                    assert result is True


def test_welcome_screen_reject(mock_console):
    with patch("siyarix.onboarding.Prompt.ask", return_value="e"):
        wizard = OnboardingWizard(console=mock_console)
        assert wizard._welcome_screen() is False


def test_welcome_screen_accept(mock_console):
    with patch("siyarix.onboarding.Prompt.ask", return_value="c"):
        wizard = OnboardingWizard(console=mock_console)
        assert wizard._welcome_screen() is True


@patch("siyarix.onboarding.shutil.which", return_value="/bin/bash")
def test_step_platform_detection(mock_which, mock_console):
    wizard = OnboardingWizard(console=mock_console)
    wizard._step_platform_detection()
    assert "platform" in wizard._choices


@pytest.mark.asyncio
@patch("siyarix.onboarding.shutil.which", return_value="/bin/true")
@patch("siyarix.onboarding.get_config_dir")
async def test_step_requirements(mock_get_config, mock_which, tmp_path, mock_console):
    mock_get_config.return_value = tmp_path
    wizard = OnboardingWizard(console=mock_console)
    with patch("sys.exit") as mock_exit:
        await wizard._step_requirements()
        mock_exit.assert_not_called()


@pytest.mark.asyncio
@patch("siyarix.onboarding.shutil.which", return_value="/bin/pip")
async def test_step_dependencies(mock_which, mock_console):
    with patch("siyarix.onboarding.Confirm.ask", return_value=False):
        wizard = OnboardingWizard(console=mock_console)
        await wizard._step_dependencies()


@pytest.mark.asyncio
@patch("siyarix.onboarding.shutil.which", return_value="/bin/true")
async def test_step_tool_discovery(mock_which, mock_console):
    wizard = OnboardingWizard(console=mock_console)
    await wizard._step_tool_discovery()
    assert len(wizard._choices["tools_installed"]) > 0


def test_step_credential_setup(mock_console):
    with patch("siyarix.onboarding.Prompt.ask", return_value="password123"):
        cred_store = MagicMock()
        cred_store.has_master_key.return_value = False
        wizard = OnboardingWizard(console=mock_console, cred_store=cred_store)
        wizard._step_credential_setup()
        pass


@pytest.mark.asyncio
async def test_step_provider_skip(mock_console):
    with patch("siyarix.onboarding.Prompt.ask", return_value="5"):
        wizard = OnboardingWizard(console=mock_console)
        await wizard._step_provider()
        assert wizard._choices["provider_type"] == "skip"


def test_step_mode(mock_console):
    with patch("siyarix.onboarding.Prompt.ask", return_value="1"):
        wizard = OnboardingWizard(console=mock_console)
        wizard._step_mode()
        assert wizard._choices["mode"] in ["integrated", "autonomous", "research"]


def test_step_persona_sysmsg(mock_console):
    with patch("siyarix.onboarding.Prompt.ask", return_value="1"):
        wizard = OnboardingWizard(console=mock_console)
        # Using "1" which parses properly
        wizard._step_persona_sysmsg()
        assert wizard._choices["persona"] != ""


def test_step_install_persona_tools(mock_console):
    with patch("siyarix.onboarding.Confirm.ask", return_value=False):
        wizard = OnboardingWizard(console=mock_console)
        wizard._choices["persona"] = "penetration_tester"
        wizard._step_install_persona_tools()


def test_step_preferences(mock_console):
    with patch("siyarix.onboarding.Prompt.ask", return_value="1"):
        wizard = OnboardingWizard(console=mock_console)
        wizard._step_preferences()
        assert "theme" in wizard._choices["preferences"]


@pytest.mark.asyncio
async def test_step_network_diagnostics(mock_console):
    wizard = OnboardingWizard(console=mock_console)
    wizard._pause = MagicMock()
    with patch(
        "httpx.get",
        return_value=MagicMock(status_code=200, elapsed=MagicMock(total_seconds=lambda: 0.1)),
    ):
        with patch(
            "siyarix.onboarding.socket.getaddrinfo",
            return_value=[(None, None, None, None, ("8.8.8.8", 80))],
        ):
            await wizard._step_network_diagnostics()
    assert wizard._choices["network_ok"] is True


@pytest.mark.asyncio
@patch("siyarix.onboarding.get_config_dir")
async def test_finalize(mock_get_config, tmp_path, mock_console):
    mock_get_config.return_value = tmp_path
    settings = MagicMock()
    wizard = OnboardingWizard(console=mock_console, settings=settings)
    wizard._choices["provider_type"] = "skip"
    with patch("sys.exit"):
        await wizard._finalize()
    settings.set.assert_called_with("onboarding_complete", True)
