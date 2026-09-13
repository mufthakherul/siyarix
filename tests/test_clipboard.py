# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for cross-platform clipboard integration and /copy chat command."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from siyarix.chat.commands import CommandRegistry
from siyarix.chat.handlers import CommandHandlersMixin
from siyarix.chat.session import ChatMessage, ChatSession
from siyarix.clipboard import copy_to_clipboard, get_from_clipboard


def test_copy_to_clipboard_empty():
    assert copy_to_clipboard("") is False


def test_copy_to_clipboard_pyperclip():
    mock_pyperclip = MagicMock()
    with patch.dict(sys.modules, {"pyperclip": mock_pyperclip}):
        assert copy_to_clipboard("test text") is True
        mock_pyperclip.copy.assert_called_once_with("test text")


def test_get_from_clipboard_pyperclip():
    mock_pyperclip = MagicMock()
    mock_pyperclip.paste.return_value = "hello from paste"
    with patch.dict(sys.modules, {"pyperclip": mock_pyperclip}):
        assert get_from_clipboard() == "hello from paste"


def test_copy_to_clipboard_subprocess_mock():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        with patch.dict(sys.modules, {"pyperclip": None}):
            assert copy_to_clipboard("data") is True
            assert mock_run.called


def test_command_registry_has_copy():
    cmd = CommandRegistry.get("/copy")
    assert cmd is not None
    assert "/cp" in cmd.aliases
    assert "/clipboard" in cmd.aliases
    assert cmd.handler == "_cmd_copy"


class DummyChat(CommandHandlersMixin):
    def __init__(self):
        self._session = ChatSession(session_id="test-session-123")
        self._command_history = ["nmap -sV 10.0.0.1", "whoami"]
        self._active_plan = None


def test_cmd_copy_last():
    chat = DummyChat()
    chat._session.messages.append(
        ChatMessage(role="user", content="scan target", timestamp=datetime.now(timezone.utc))
    )
    chat._session.messages.append(
        ChatMessage(
            role="assistant",
            content="Here is the scan finding:\nPort 80 is open.",
            timestamp=datetime.now(timezone.utc),
        )
    )

    with patch("siyarix.clipboard.copy_to_clipboard", return_value=True) as mock_copy:
        chat._cmd_copy("last")
        mock_copy.assert_called_once()
        assert "Port 80 is open." in mock_copy.call_args[0][0]


def test_cmd_copy_code():
    chat = DummyChat()
    chat._session.messages.append(
        ChatMessage(
            role="assistant",
            content="Use this script:\n```python\nimport socket\ns = socket.socket()\n```\nDone!",
            timestamp=datetime.now(timezone.utc),
        )
    )

    with patch("siyarix.clipboard.copy_to_clipboard", return_value=True) as mock_copy:
        chat._cmd_copy("code")
        mock_copy.assert_called_once()
        assert "import socket" in mock_copy.call_args[0][0]
        assert "```" not in mock_copy.call_args[0][0]


def test_cmd_copy_all():
    chat = DummyChat()
    chat._session.messages.append(
        ChatMessage(role="user", content="ping", timestamp=datetime.now(timezone.utc))
    )
    chat._session.messages.append(
        ChatMessage(role="assistant", content="pong", timestamp=datetime.now(timezone.utc))
    )

    with patch("siyarix.clipboard.copy_to_clipboard", return_value=True) as mock_copy:
        chat._cmd_copy("all")
        mock_copy.assert_called_once()
        copied_text = mock_copy.call_args[0][0]
        assert "USER" in copied_text
        assert "ping" in copied_text
        assert "ASSISTANT" in copied_text
        assert "pong" in copied_text


def test_cmd_copy_no_messages():
    chat = DummyChat()
    with patch("siyarix.clipboard.copy_to_clipboard") as mock_copy:
        chat._cmd_copy("")
        mock_copy.assert_not_called()
