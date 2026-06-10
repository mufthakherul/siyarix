# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the SiyarixChat REPL and chat data models."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.chat import (
    ChatMessage,
    ChatSession,
    CommandProfile,
    CommandProfileStore,
    SiyarixChat,
    _Shell,
    build_platform_context,
    detect_shell,
    normalize_shell,
    start_chat,
)


# ── Data Model Tests ───────────────────────────────────────────────────


class TestChatMessage:
    def test_create_message(self) -> None:
        msg = ChatMessage(role="user", content="scan 10.0.0.1")
        assert msg.role == "user"
        assert msg.content == "scan 10.0.0.1"
        assert isinstance(msg.timestamp, datetime)

    def test_to_dict(self) -> None:
        msg = ChatMessage(role="assistant", content="hello", metadata={"key": "val"})
        d = msg.to_dict()
        assert d["role"] == "assistant"
        assert d["content"] == "hello"
        assert d["metadata"] == {"key": "val"}
        assert "timestamp" in d


class TestChatSession:
    def test_create_session(self) -> None:
        session = ChatSession(session_id="test-123")
        assert session.session_id == "test-123"
        assert session.messages == []
        assert session.mode == "integrated"

    def test_add_message(self) -> None:
        session = ChatSession(session_id="s1")
        msg = session.add_message("user", "hello")
        assert len(session.messages) == 1
        assert msg.role == "user"
        assert msg.content == "hello"

    def test_last_n(self) -> None:
        session = ChatSession(session_id="s1")
        for i in range(10):
            session.add_message("user", f"msg{i}")
        last = session.last_n(3)
        assert len(last) == 3
        assert last[0].content == "msg7"

    def test_get_context_summary_empty(self) -> None:
        session = ChatSession(session_id="s1")
        assert session.get_context_summary() == ""

    def test_get_context_summary(self) -> None:
        session = ChatSession(session_id="s1")
        session.add_message("user", "scan target")
        session.add_message("assistant", "scanning...")
        summary = session.get_context_summary()
        assert "User" in summary
        assert "Siyarix" in summary
        assert "scan target" in summary

    def test_save_and_load(self, tmp_path: Path) -> None:
        path = tmp_path / "session.json"
        session = ChatSession(session_id="s1", target="10.0.0.1", mode="autonomous")
        session.add_message("user", "hello")
        session.add_message("assistant", "hi")
        session.save(path)
        assert path.exists()

        loaded = ChatSession.load(path)
        assert loaded.session_id == "s1"
        assert loaded.target == "10.0.0.1"
        assert loaded.mode == "autonomous"
        assert len(loaded.messages) == 2
        assert loaded.messages[0].content == "hello"
        assert loaded.messages[1].content == "hi"


class TestCommandProfileStore:
    def test_save_and_get(self) -> None:
        store = CommandProfileStore()
        profile = CommandProfile(name="test", command="nmap -sV")
        store.save(profile)
        assert store.get("test") is None  # stub: always returns None
        assert store.list_credentials() == []
        store.delete("test")  # should not raise


# ── Helper Function Tests ──────────────────────────────────────────────


class TestHelpers:
    def test_build_platform_context(self) -> None:
        ctx = build_platform_context()
        assert "platform_pretty" in ctx
        assert "arch" in ctx
        assert "hostname" in ctx
        assert "python_version" in ctx

    def test_detect_shell(self) -> None:
        shell = detect_shell()
        assert isinstance(shell, str)

    def test_normalize_shell(self) -> None:
        result = normalize_shell("/bin/bash")
        assert isinstance(result, _Shell)
        assert result.value == "/bin/bash"


# ── SiyarixChat Tests ──────────────────────────────────────────────────


class TestSiyarixChatInit:
    def test_init_defaults(self) -> None:
        chat = SiyarixChat()
        assert chat._mode == "integrated"
        assert chat._session is not None
        assert chat._session.session_id is not None

    def test_init_with_target(self) -> None:
        chat = SiyarixChat(target="10.0.0.1")
        assert chat._session.target == "10.0.0.1"

    def test_init_with_mode(self) -> None:
        chat = SiyarixChat(mode="autonomous")
        assert chat._mode == "autonomous"

    def test_init_resume_session(self, tmp_path: Path) -> None:
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir(parents=True)
        session = ChatSession(session_id="resume-1")
        session.add_message("user", "hello")
        session.save(sessions_dir / "resume-1.json")

        with patch.object(SiyarixChat, "_SESSIONS_DIR", sessions_dir):
            chat = SiyarixChat(session_id="resume-1", resume=True)
            assert chat._session.session_id == "resume-1"
            assert len(chat._session.messages) == 1
            assert chat._session.messages[0].content == "hello"


class TestSiyarixChatSlashCommands:
    @pytest.fixture
    def chat(self) -> SiyarixChat:
        return SiyarixChat()

    @pytest.mark.asyncio
    async def test_handle_slash_help(self, chat: SiyarixChat) -> None:
        with patch.object(chat, "_cmd_help") as mock:
            await chat._handle_slash("/help")
            mock.assert_called_once_with("")

    @pytest.mark.asyncio
    async def test_handle_slash_unknown(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock_console:
            await chat._handle_slash("/nonexistent")
            mock_console.print.assert_called_once()
            args = mock_console.print.call_args[0][0]
            assert "Unknown command" in str(args)

    @pytest.mark.asyncio
    async def test_handle_slash_exit(self, chat: SiyarixChat) -> None:
        await chat._handle_slash("/exit")
        assert chat._running is False

    @pytest.mark.asyncio
    async def test_handle_slash_quit(self, chat: SiyarixChat) -> None:
        await chat._handle_slash("/quit")
        assert chat._running is False

    def test_cmd_exit(self, chat: SiyarixChat) -> None:
        assert chat._running is True
        chat._cmd_exit("")
        assert chat._running is False

    def test_cmd_clear(self, chat: SiyarixChat) -> None:
        chat._session.add_message("user", "test")
        assert len(chat._session.messages) == 1
        with patch("siyarix.chat.console") as mock:
            chat._cmd_clear("")
            assert len(chat._session.messages) == 0
            mock.clear.assert_called_once()

    def test_cmd_new(self, chat: SiyarixChat) -> None:
        chat._session.add_message("user", "test")
        chat._session.context["key"] = "val"
        with patch("siyarix.chat.console") as mock:
            chat._cmd_new("")
            assert len(chat._session.messages) == 0
            assert chat._session.context == {}
            mock.print.assert_called_once()

    def test_cmd_reset(self, chat: SiyarixChat) -> None:
        chat._mode = "autonomous"
        chat._session.mode = "autonomous"
        chat._session.target = "10.0.0.1"
        with patch("siyarix.chat.console") as mock:
            chat._cmd_reset("")
            assert chat._mode == "integrated"
            assert chat._session.target == ""
            mock.print.assert_called_once()

    def test_cmd_version(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_version("")
            mock.print.assert_called_once()
            args = mock.print.call_args[0][0]
            assert "Siyarix" in str(args)

    def test_cmd_target_set(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_target("10.0.0.1")
            assert chat._session.target == "10.0.0.1"
            mock.print.assert_called_once()

    def test_cmd_target_show(self, chat: SiyarixChat) -> None:
        chat._session.target = "10.0.0.1"
        with patch("siyarix.chat.console") as mock:
            chat._cmd_target("")
            mock.print.assert_called_once()
            args = mock.print.call_args[0][0]
            assert "10.0.0.1" in str(args)

    def test_cmd_mode_switch(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_mode("autonomous")
            assert chat._mode == "autonomous"
            mock.print.assert_called_once()

    def test_cmd_mode_invalid(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_mode("invalid")
            assert chat._mode == "integrated"
            mock.print.assert_any_call(
                "[red]Invalid mode: invalid. Valid modes: autonomous, integrated, registry, offline[/red]"
            )

    def test_cmd_uptime(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_uptime("")
            mock.print.assert_called_once()
            args = mock.print.call_args[0][0]
            assert "uptime" in str(args).lower()

    def test_cmd_save(self, chat: SiyarixChat) -> None:
        with (
            patch("siyarix.chat.console") as mock,
            patch.object(chat._session, "save") as mock_save,
        ):
            chat._cmd_save("")
            mock_save.assert_called_once()
            mock.print.assert_called_once()

    def test_cmd_history_empty(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_history("")
            mock.print.assert_called_once()

    def test_cmd_history_with_messages(self, chat: SiyarixChat) -> None:
        chat._session.add_message("user", "test message")
        chat._session.add_message("assistant", "response")
        with patch("siyarix.chat.console") as mock:
            chat._cmd_history("")
            assert mock.print.call_count >= 1

    def test_cmd_esc(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_esc("")
            assert chat._esc_press_count == 1
            mock.print.assert_any_call("[bold red]⚠ EMERGENCY STOP TRIGGERED[/bold red]")

    def test_cmd_context_empty(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_context("")
            mock.print.assert_called_once()

    def test_cmd_env(self, chat: SiyarixChat) -> None:
        with patch("siyarix.chat.console") as mock:
            chat._cmd_env("")
            mock.print.assert_called_once()


class TestGenerateTextResponse:
    @pytest.fixture
    def chat(self) -> SiyarixChat:
        return SiyarixChat()

    def test_hello(self, chat: SiyarixChat) -> None:
        response = chat._generate_text_response("hello")
        assert response is not None
        assert "Siyarix" in response

    def test_help(self, chat: SiyarixChat) -> None:
        response = chat._generate_text_response("help")
        assert response is not None
        assert "Siyarix" in response

    def test_generic(self, chat: SiyarixChat) -> None:
        response = chat._generate_text_response("some random query")
        assert response is None

    def test_how_to(self, chat: SiyarixChat) -> None:
        response = chat._generate_text_response("how to scan a network")
        assert response is None


class TestProviderStatus:
    @pytest.fixture
    def chat(self) -> SiyarixChat:
        return SiyarixChat()

    def test_gather_provider_status_no_keys(self, chat: SiyarixChat) -> None:
        with patch.dict("os.environ", {}, clear=True):
            status = chat._gather_provider_status()
            assert isinstance(status, dict)
            assert "openai" in status
            assert "gemini" in status
            assert "ollama" in status

    def test_gather_provider_status_with_keys(self, chat: SiyarixChat) -> None:
        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "sk-test",
                "GEMINI_API_KEY": "test-key",
            },
        ):
            status = chat._gather_provider_status()
            assert status["openai"][0] in ("✓", "✗", "⚠")
            assert status["gemini"][0] in ("✓", "✗", "⚠")


class TestSiarixChatSessionPersistence:
    def test_session_save_load_roundtrip(self, tmp_path: Path) -> None:
        session = ChatSession(session_id="roundtrip")
        session.add_message("user", "scan target")
        session.add_message("assistant", "done")
        session.target = "10.0.0.1"
        session.mode = "autonomous"

        path = tmp_path / "roundtrip.json"
        session.save(path)

        loaded = ChatSession.load(path)
        assert loaded.session_id == "roundtrip"
        assert loaded.target == "10.0.0.1"
        assert loaded.mode == "autonomous"
        assert len(loaded.messages) == 2
        assert loaded.messages[0].content == "scan target"
        assert loaded.messages[1].content == "done"

    def test_session_save_load_empty(self, tmp_path: Path) -> None:
        session = ChatSession(session_id="empty")
        path = tmp_path / "empty.json"
        session.save(path)
        loaded = ChatSession.load(path)
        assert loaded.session_id == "empty"
        assert loaded.messages == []


class TestStartChat:
    def test_start_chat_calls_run(self) -> None:
        with (
            patch("siyarix.chat.SiyarixChat") as mock_cls,
        ):
            mock_instance = MagicMock()
            mock_cls.return_value = mock_instance

            start_chat()
            mock_cls.assert_called_once_with(
                mode="integrated", target="", session_id=None, resume=False
            )
            mock_instance.run.assert_called_once()

    def test_start_chat_with_params(self) -> None:
        with (
            patch("siyarix.chat.SiyarixChat") as mock_cls,
        ):
            mock_instance = MagicMock()
            mock_cls.return_value = mock_instance

            start_chat(mode="autonomous", target="10.0.0.1", session_id="custom")
            mock_cls.assert_called_once_with(
                mode="autonomous", target="10.0.0.1", session_id="custom", resume=False
            )
            mock_instance.run.assert_called_once()
