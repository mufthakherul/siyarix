import pytest
import os
from unittest.mock import MagicMock, patch, AsyncMock
from siyarix.chat import SiyarixChat
from siyarix.chat.commands import CommandProfile


@pytest.fixture
def chat():
    return SiyarixChat()


@pytest.fixture
def mock_console():
    from siyarix.chat.console import console

    with patch.object(console, "print") as mock_print, patch.object(console, "clear") as mock_clear:
        yield MagicMock(print=mock_print, clear=mock_clear)


@patch("siyarix.chat.handlers.datetime")
def test_cmd_status(mock_dt, chat, mock_console):
    from datetime import datetime, timezone

    mock_dt.now.return_value = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    chat._session.created_at = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    chat._cmd_status("")
    mock_console.print.assert_called_once()
    panel = mock_console.print.call_args[0][0]
    content = str(getattr(panel, "renderable", panel))
    assert "Mode:" in content
    assert "Provider:" in content


def test_cmd_session(chat, mock_console):
    chat._cmd_session("")
    mock_console.print.assert_called_once()


def test_cmd_shells(chat, mock_console):
    chat._cmd_shells("")
    mock_console.print.assert_called_once()


def test_cmd_search_empty(chat, mock_console):
    chat._cmd_search(" ")
    mock_console.print.assert_any_call("[yellow]Usage: /search <keyword>[/yellow]")


def test_cmd_search_found(chat, mock_console):
    chat._session.add_message("user", "test scan query")
    chat._cmd_search("scan")
    mock_console.print.assert_called()


def test_cmd_search_not_found(chat, mock_console):
    chat._session.add_message("user", "test scan query")
    chat._cmd_search("nothing")
    mock_console.print.assert_any_call("[dim]No matches for 'nothing'.[/dim]")


def test_cmd_examples(chat, mock_console):
    chat._cmd_examples("")
    mock_console.print.assert_called_once()


@patch("siyarix.chat.handlers.CommandProfileStore")
def test_cmd_savecmd(mock_store_class, chat, mock_console):
    mock_store = MagicMock()
    mock_store_class.return_value = mock_store

    chat._cmd_savecmd("nmap nmap -sV")
    mock_store.save.assert_called_once()
    mock_console.print.assert_any_call("[green]✓ Saved command profile: nmap[/green]")

    chat._cmd_savecmd("")
    mock_console.print.assert_any_call("[yellow]Usage: /savecmd <name> <command>[/yellow]")


@patch("siyarix.chat.handlers.CommandProfileStore")
def test_cmd_cmds(mock_store_class, chat, mock_console):
    mock_store = MagicMock()
    mock_store_class.return_value = mock_store

    mock_store.list_credentials.return_value = []
    chat._cmd_cmds("")
    mock_console.print.assert_any_call("[dim]No saved command profiles.[/dim]")

    mock_store.list_credentials.return_value = [CommandProfile(name="test", command="testcmd")]
    chat._cmd_cmds("")
    assert mock_console.print.call_count >= 2


@patch("siyarix.chat.handlers.CommandProfileStore")
@patch("siyarix.chat.handlers.Prompt.ask")
@pytest.mark.asyncio
async def test_cmd_cmd(mock_ask, mock_store_class, chat, mock_console):
    mock_store = MagicMock()
    mock_store_class.return_value = mock_store

    mock_store.get.return_value = None
    await chat._cmd_cmd("nonexistent")
    mock_console.print.assert_any_call("[red]Profile not found: nonexistent[/red]")

    mock_store.get.return_value = CommandProfile(name="test", command="testcmd")
    mock_ask.return_value = "y"

    chat._execute_instruction = AsyncMock()
    await chat._cmd_cmd("test")
    chat._execute_instruction.assert_called_once_with("testcmd")


def test_cmd_theme_list(chat, mock_console):
    chat._cmd_theme("")
    assert mock_console.print.call_count >= 3


def test_cmd_theme_set(chat, mock_console):
    with patch("siyarix.chat.handlers.print_theme_preview"):
        chat._cmd_theme("cyber-noir")
        assert chat._settings.get("color_theme") == "cyber-noir"


def test_cmd_translate(chat, mock_console):
    chat._cmd_translate("scan")
    mock_console.print.assert_called()

    mock_console.print.reset_mock()
    chat._cmd_translate("nonexistent_intent_xyz")
    mock_console.print.assert_any_call("[red]Unknown intent: nonexistent_intent_xyz[/red]")


def test_cmd_intents(chat, mock_console):
    chat._cmd_intents("")
    mock_console.print.assert_called()
    mock_console.print.reset_mock()

    chat._cmd_intents("scan")
    mock_console.print.assert_called()


def test_cmd_split(chat, mock_console):
    chat._render_split_pane_layout = MagicMock()
    chat._cmd_split("metrics")
    assert chat._split_pane_enabled is True
    assert chat._split_pane_type == "metrics"
    mock_console.print.assert_any_call("[green]Split Pane enabled. System view: METRICS[/green]")
    chat._render_split_pane_layout.assert_called_once()

    chat._cmd_split("off")
    assert chat._split_pane_enabled is False
    mock_console.print.assert_any_call("[yellow]Split Pane view disabled.[/yellow]")


@patch("siyarix.report.ReportEngine", create=True)
@patch("siyarix.report.ReportConfig", create=True)
def test_cmd_report(_mock_config, mock_engine_class, chat, mock_console):
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine
    mock_engine.save.return_value = "/tmp/report.md"

    chat._SESSIONS_DIR = MagicMock()
    chat._SESSIONS_DIR.__truediv__.return_value = MagicMock()

    chat._cmd_report("markdown")
    mock_engine.build_report.assert_called_once()
    mock_engine.save.assert_called_once()


@patch("siyarix.chat.handlers.Prompt.ask")
def test_cmd_key_set_env(mock_ask, chat, mock_console):
    with patch.dict("os.environ", {}):
        mock_ask.return_value = "test-key"
        with patch("siyarix.credential_store.CredentialStore", side_effect=Exception("No store")):
            chat._cmd_key("set openai")
            assert os.environ.get("OPENAI_API_KEY") == "test-key"
            mock_console.print.assert_any_call("[green]✓ openai API key set in environment[/green]")
            mock_console.print.assert_any_call(
                "[dim]Tip: Key will only last for this session. Install cryptography for persistent storage: pip install cryptography[/dim]"
            )


@patch("siyarix.chat.handlers.Prompt.ask")
def test_cmd_key_remove(mock_ask, chat, mock_console):
    with patch.dict("os.environ", {"OPENAI_API_KEY": "test"}):
        with patch("siyarix.credential_store.CredentialStore") as mock_store_class:
            mock_store = MagicMock()
            mock_store_class.return_value = mock_store
            chat._cmd_key("remove openai")
            assert "OPENAI_API_KEY" not in os.environ
            mock_store.delete.assert_called_once_with("openai", "api_key")
            mock_console.print.assert_any_call("[green]✓ Cleared openai API key[/green]")


def test_cmd_key_show(chat, mock_console):
    with patch("siyarix.chat.handlers.CommandHandlersMixin._show_key_status") as mock_show:
        chat._cmd_key("show")
        mock_show.assert_called_once()


def test_cmd_help(chat, mock_console):
    chat._cmd_help("")
    assert mock_console.print.called


def test_cmd_report_invalid(chat, mock_console):
    chat._cmd_report("pdf")
    mock_console.print.assert_any_call("[yellow]Invalid format. Use 'markdown' or 'html'.[/yellow]")


@patch.dict("sys.modules", {"siyarix.report": None})
def test_cmd_report_no_engine(chat, mock_console):
    chat._cmd_report("html")
    mock_console.print.assert_any_call(
        "[yellow]Report generation is not available in this version[/yellow]"
    )


@patch("siyarix.report.ReportEngine", create=True)
@patch("siyarix.report.ReportConfig", create=True)
def test_cmd_report_html(_mock_config, mock_engine_class, chat, mock_console):
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine
    mock_engine.save.return_value = "/tmp/report.html"
    chat._SESSIONS_DIR = MagicMock()
    chat._cmd_report("html")
    mock_engine.build_report.assert_called_once()
    mock_engine.save.assert_called_once()


def test_cmd_savecmd_no_args(chat, mock_console):
    chat._cmd_savecmd("")
    mock_console.print.assert_any_call("[yellow]Usage: /savecmd <name> <command>[/yellow]")


def test_cmd_savecmd_missing_cmd(chat, mock_console):
    chat._cmd_savecmd("nmap")
    mock_console.print.assert_any_call("[yellow]Provide both a name and command.[/yellow]")


@patch("siyarix.chat.handlers.CommandProfileStore")
@patch("siyarix.chat.handlers.Prompt.ask")
@pytest.mark.asyncio
async def test_cmd_cmd_no_run(mock_ask, mock_store_class, chat, mock_console):
    mock_store = MagicMock()
    mock_store_class.return_value = mock_store
    mock_store.get.return_value = CommandProfile(name="test", command="testcmd")
    mock_ask.return_value = "n"
    chat._execute_instruction = AsyncMock()
    await chat._cmd_cmd("test")
    chat._execute_instruction.assert_not_called()


def test_show_key_status(chat, mock_console):
    with (
        patch("siyarix.providers.ProviderManager.get_instance") as mock_pm,
        patch("siyarix.credential_store.CredentialStore") as mock_cs,
    ):
        mock_registry = MagicMock()
        mock_pm.return_value = mock_registry
        mock_registry.list_providers.return_value = ["openai", "anthropic"]
        profile_openai = MagicMock(api_key_env="OPENAI_API_KEY")
        profile_anthropic = MagicMock(api_key_env="ANTHROPIC_API_KEY")
        mock_registry.get_profile.side_effect = (
            lambda p: profile_openai if p == "openai" else profile_anthropic
        )

        mock_store = MagicMock()
        mock_cs.return_value = mock_store
        mock_store.retrieve.side_effect = lambda p, k: True if p == "openai" else False

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "123"}):
            chat._show_key_status()
            mock_console.print.assert_called()


@patch("siyarix.chat.handlers.Prompt.ask")
def test_cmd_key_rotate(mock_ask, chat, mock_console):
    with patch("siyarix.credential_store.CredentialStore") as mock_cs:
        mock_store = MagicMock()
        mock_cs.return_value = mock_store
        mock_ask.return_value = "newpass"
        mock_store.rotate_key.return_value = True
        chat._cmd_key("rotate")
        mock_console.print.assert_any_call(
            "[green]✓ Master encryption key rotated successfully[/green]"
        )
