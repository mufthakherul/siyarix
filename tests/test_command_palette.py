# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from siyarix.ux.command_palette import CommandPalette


@pytest.fixture
def palette() -> CommandPalette:
    with patch("siyarix.ux.command_palette.CommandProfileStore") as mock_store:
        instance = MagicMock()
        instance.list_profiles.return_value = []
        instance.extract_placeholders.return_value = []
        mock_store.return_value = instance
        yield CommandPalette(session_id="test-session")


@pytest.fixture
def mock_console() -> MagicMock:
    return MagicMock(spec=Console)


class TestCommandPalette:
    def test_init_default_session(self) -> None:
        with patch("siyarix.ux.command_palette.CommandProfileStore"):
            p = CommandPalette()
            assert p.session_id == ""

    def test_init_with_session(self) -> None:
        with patch("siyarix.ux.command_palette.CommandProfileStore"):
            p = CommandPalette(session_id="sess-01")
            assert p.session_id == "sess-01"

    def test_core_actions_present(self, palette: CommandPalette) -> None:
        assert len(palette._core_actions) == 10
        assert "nmap scan full" in palette._core_actions
        assert "wizard launch" in palette._core_actions

    def test_get_search_options_core_actions(self, palette: CommandPalette) -> None:
        options = palette.get_search_options()
        action_options = [o for o in options if o.startswith("action:")]
        assert len(action_options) == 10

    def test_get_search_options_with_profiles(self) -> None:
        with patch("siyarix.ux.command_palette.CommandProfileStore") as mock_store:
            instance = MagicMock()
            profile = MagicMock()
            profile.name = "web-scan"
            profile.command = "nmap -sV"
            profile.description = "Web scan profile"
            instance.list_profiles.return_value = [profile]
            instance.extract_placeholders.return_value = []
            mock_store.return_value = instance
            p = CommandPalette()
            options = p.get_search_options()
            profile_options = [o for o in options if o.startswith("profile:")]
            assert len(profile_options) == 1

    def test_get_search_options_with_history(self) -> None:
        with (
            patch("siyarix.ux.command_palette.CommandProfileStore") as mock_store,
            patch("siyarix.ux.command_palette.command_history") as mock_history,
        ):
            instance = MagicMock()
            instance.list_profiles.return_value = []
            instance.extract_placeholders.return_value = []
            mock_store.return_value = instance
            mock_history.recent.return_value = [
                {"command": "nmap -sV 10.0.0.1"},
                {"command": "nuclei -u example.com"},
            ]
            p = CommandPalette()
            options = p.get_search_options()
            history_options = [o for o in options if o.startswith("history:")]
            assert len(history_options) == 2

    def test_get_search_options_history_exception(self) -> None:
        with (
            patch("siyarix.ux.command_palette.CommandProfileStore") as mock_store,
            patch("siyarix.ux.command_palette.command_history") as mock_history,
        ):
            instance = MagicMock()
            instance.list_profiles.return_value = []
            instance.extract_placeholders.return_value = []
            mock_store.return_value = instance
            mock_history.recent.side_effect = Exception("DB error")
            p = CommandPalette()
            options = p.get_search_options()
            assert len(options) == 10

    def test_show_cancelled_keyboard_interrupt(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", side_effect=KeyboardInterrupt()),
        ):
            result = palette.show(mock_console)
            assert result is None
            mock_console.print.assert_called()

    def test_show_no_query(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", return_value=""),
        ):
            result = palette.show(mock_console)
            assert result is None

    def test_show_no_matches(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", return_value="zzzznothing"),
        ):
            result = palette.show(mock_console)
            assert result is None

    def test_show_with_prompt_toolkit(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", True),
            patch("siyarix.ux.command_palette.WordCompleter"),
            patch("siyarix.ux.command_palette.ptk_prompt", return_value="nmap"),
            patch("rich.prompt.Prompt.ask", return_value="1"),
        ):
            result = palette.show(mock_console)
            assert result is not None

    def test_show_no_selection(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", side_effect=["nmap", ""]),
        ):
            result = palette.show(mock_console)
            assert result is None

    def test_show_invalid_index(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", side_effect=["nmap", "999"]),
        ):
            result = palette.show(mock_console)
            assert result is None

    def test_show_non_integer_selection(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", side_effect=["nmap", "abc"]),
        ):
            result = palette.show(mock_console)
            assert result is None

    def test_map_action_to_cmd_known(self, palette: CommandPalette) -> None:
        assert palette._map_action_to_cmd("nmap scan full") == "nmap -sV -sC -O -p 1-65535"
        assert palette._map_action_to_cmd("nuclei scan") == "nuclei -severity critical,high"
        assert palette._map_action_to_cmd("wizard launch") == "wizard"

    def test_map_action_to_cmd_unknown(self, palette: CommandPalette) -> None:
        assert palette._map_action_to_cmd("unknown action") == "unknown action"

    def test_substitute_placeholders_no_placeholders(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with patch.object(palette._profile_store, "extract_placeholders", return_value=[]):
            result = palette._substitute_placeholders(mock_console, "nmap -sV")
            assert result == "nmap -sV"

    def test_substitute_placeholders_with_params(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch.object(palette._profile_store, "extract_placeholders", return_value=["target"]),
            patch.object(palette._profile_store, "render", return_value="nmap -sV 10.0.0.1"),
            patch("rich.prompt.Prompt.ask", return_value="10.0.0.1"),
        ):
            result = palette._substitute_placeholders(mock_console, "nmap -sV ${target}")
            assert result == "nmap -sV 10.0.0.1"

    def test_get_search_options_does_not_duplicate_core_in_history(self) -> None:
        with (
            patch("siyarix.ux.command_palette.CommandProfileStore") as mock_store,
            patch("siyarix.ux.command_palette.command_history") as mock_history,
        ):
            instance = MagicMock()
            instance.list_profiles.return_value = []
            instance.extract_placeholders.return_value = []
            mock_store.return_value = instance
            mock_history.recent.return_value = [{"command": "nmap scan full"}]
            p = CommandPalette()
            options = p.get_search_options()
            action_count = len([o for o in options if o.startswith("action:")])
            assert action_count == 10

    def test_show_exception_during_prompt(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", side_effect=Exception("Unexpected")),
        ):
            result = palette.show(mock_console)
            assert result is None

    def test_show_select_action(self) -> None:
        with (
            patch("siyarix.ux.command_palette.CommandProfileStore") as mock_store,
            patch("siyarix.ux.command_palette.command_history") as mock_history,
        ):
            instance = MagicMock()
            instance.list_profiles.return_value = []
            instance.extract_placeholders.return_value = []
            mock_store.return_value = instance
            mock_history.recent.return_value = []
            p = CommandPalette()
            console = MagicMock(spec=Console)
            with (
                patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
                patch("rich.prompt.Prompt.ask", side_effect=["nmap", "1"]),
            ):
                result = p.show(console)
                assert result is not None

    def test_show_select_profile(self) -> None:
        profile = MagicMock()
        profile.name = "my-scan"
        profile.command = "nmap -sV ${target}"
        profile.description = "My scan"
        with (
            patch("siyarix.ux.command_palette.CommandProfileStore") as mock_store,
            patch("siyarix.ux.command_palette.command_history") as mock_history,
        ):
            instance = MagicMock()
            instance.list_profiles.return_value = [profile]
            instance.extract_placeholders.return_value = ["target"]
            instance.render.return_value = "nmap -sV 10.0.0.1"
            mock_store.return_value = instance
            mock_history.recent.return_value = []
            p = CommandPalette()
            console = MagicMock(spec=Console)
            with (
                patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
                patch("rich.prompt.Prompt.ask", side_effect=["my-scan", "1", "10.0.0.1"]),
            ):
                result = p.show(console)
                assert result is not None

    def test_show_ptk_without_completer_fallback(self, palette: CommandPalette, mock_console: MagicMock) -> None:
        with (
            patch("siyarix.ux.command_palette.PTK_AVAILABLE", False),
            patch("rich.prompt.Prompt.ask", side_effect=["dashboard", "1"]),
        ):
            result = palette.show(mock_console)
            assert result == "dashboard"
