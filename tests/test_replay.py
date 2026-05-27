from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from siyarix.session.replay import CommandReplayer


@pytest.fixture
def mock_history() -> MagicMock:
    with patch("siyarix.session.replay.command_history") as m:
        yield m


@pytest.fixture
def replayer(mock_history: MagicMock) -> CommandReplayer:
    return CommandReplayer()


@pytest.fixture
def replayer_with_console() -> tuple[CommandReplayer, MagicMock]:
    mock_console = MagicMock(spec=Console)
    return CommandReplayer(console=mock_console), mock_console


class TestCommandReplayer:
    def test_init_default_console(self) -> None:
        r = CommandReplayer()
        assert isinstance(r.console, Console)

    def test_init_custom_console(self) -> None:
        c = Console()
        r = CommandReplayer(console=c)
        assert r.console is c

    def test_list_recent_with_history(self, replayer: CommandReplayer, mock_history: MagicMock) -> None:
        mock_history.recent.return_value = [
            {"command": "nmap -sV 10.0.0.1", "timestamp": "2026-05-01", "result": "success"},
            {"command": "nuclei -u example.com", "timestamp": "2026-05-02", "result": "failure"},
        ]
        replayer.list_recent(limit=5)
        mock_history.recent.assert_called_once_with(limit=5)

    def test_list_recent_no_history(self, replayer: CommandReplayer, mock_history: MagicMock) -> None:
        mock_history.recent.return_value = []
        replayer.list_recent(limit=10)
        mock_history.recent.assert_called_once_with(limit=10)

    def test_replay_session_with_commands(self, replayer: CommandReplayer, mock_history: MagicMock) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        cursor.fetchall.return_value = [
            {"command": "nmap -sV 10.0.0.1"},
            {"command": "nuclei -u example.com"},
        ]
        conn.execute.return_value = cursor
        mock_history._get_conn.return_value = conn

        result = replayer.replay_session("session-123")
        assert result == ["nmap -sV 10.0.0.1", "nuclei -u example.com"]
        conn.execute.assert_called_once()

    def test_replay_session_no_commands(self, replayer: CommandReplayer, mock_history: MagicMock) -> None:
        conn = MagicMock()
        cursor = MagicMock()
        cursor.fetchall.return_value = []
        conn.execute.return_value = cursor
        mock_history._get_conn.return_value = conn

        result = replayer.replay_session("session-empty")
        assert result == []

    def test_replay_last_with_history(self, replayer: CommandReplayer, mock_history: MagicMock) -> None:
        mock_history.recent.return_value = [{"command": "last-command"}]
        result = replayer.replay_last()
        assert result == "last-command"
        mock_history.recent.assert_called_once_with(limit=1)

    def test_replay_last_no_history(self, replayer: CommandReplayer, mock_history: MagicMock) -> None:
        mock_history.recent.return_value = []
        result = replayer.replay_last()
        assert result is None

    def test_replay_session_calls_console(self, replayer_with_console: tuple[CommandReplayer, MagicMock]) -> None:
        r, console = replayer_with_console
        conn = MagicMock()
        cursor = MagicMock()
        cursor.fetchall.return_value = [{"command": "cmd1"}]
        conn.execute.return_value = cursor
        with patch("siyarix.session.replay.command_history._get_conn", return_value=conn):
            r.replay_session("sid")
        assert console.print.called

    def test_replay_session_empty_calls_console(self, replayer_with_console: tuple[CommandReplayer, MagicMock]) -> None:
        r, console = replayer_with_console
        conn = MagicMock()
        cursor = MagicMock()
        cursor.fetchall.return_value = []
        conn.execute.return_value = cursor
        with patch("siyarix.session.replay.command_history._get_conn", return_value=conn):
            r.replay_session("sid")
        assert console.print.called

    def test_list_recent_output(self, replayer_with_console: tuple[CommandReplayer, MagicMock]) -> None:
        r, console = replayer_with_console
        with patch("siyarix.session.replay.command_history.recent", return_value=[
            {"command": "nmap", "timestamp": "t1", "result": "success"},
        ]):
            r.list_recent(1)
        assert console.print.called

    def test_replay_last_returns_none_when_empty(self, replayer_with_console: tuple[CommandReplayer, MagicMock]) -> None:
        r, console = replayer_with_console
        with patch("siyarix.session.replay.command_history.recent", return_value=[]):
            result = r.replay_last()
        assert result is None

    def test_replay_last_with_console_output(self, replayer_with_console: tuple[CommandReplayer, MagicMock]) -> None:
        r, console = replayer_with_console
        with patch("siyarix.session.replay.command_history.recent", return_value=[]):
            result = r.replay_last()
        assert result is None

    def test_list_recent_formats_output(self, replayer_with_console: tuple[CommandReplayer, MagicMock]) -> None:
        r, console = replayer_with_console
        history = [
            {"command": "nmap -sV", "timestamp": "2026-05-01 10:00:00", "result": "success"},
            {"command": "nuclei -u x", "timestamp": "2026-05-01 10:01:00", "result": "failure"},
        ]
        with patch("siyarix.session.replay.command_history.recent", return_value=history):
            r.list_recent(limit=2)
        assert console.print.call_count >= 3
