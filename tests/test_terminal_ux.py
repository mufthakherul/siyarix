# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for terminal window UX, input method, output systems, and scrolling."""

from __future__ import annotations

import io
import sys
from unittest.mock import MagicMock, patch

from prompt_toolkit.formatted_text import FormattedText
from rich.console import Console

from siyarix.chat.console import (
    get_terminal_size,
    print_paged,
    set_terminal_title,
)
from siyarix.chat.prompts import make_bottom_toolbar
from siyarix.chat.repl import SiyarixChat
from siyarix.output import OutputEngine, OutputFormat


# ---------------------------------------------------------------------------
# Terminal Window & Title Tests
# ---------------------------------------------------------------------------


class TestTerminalTitle:
    def test_set_terminal_title_osc_sequence(self):
        """Verify OSC 0 escape sequence is written to stdout."""
        buf = io.StringIO()
        with patch.object(sys, "stdout", buf):
            set_terminal_title("Siyarix REPL - [integrated]")
        assert "\033]0;Siyarix REPL - [integrated]\007" in buf.getvalue()

    def test_set_terminal_title_windows_win32(self):
        """Verify Windows SetConsoleTitleW is safely called on win32."""
        with patch.object(sys, "platform", "win32"):
            with patch("ctypes.windll", create=True) as mock_windll:
                mock_kernel32 = MagicMock()
                mock_windll.kernel32 = mock_kernel32
                set_terminal_title("Test Window Title")
                mock_kernel32.SetConsoleTitleW.assert_called_once_with("Test Window Title")

    def test_set_terminal_title_handles_exceptions_gracefully(self):
        """Verify set_terminal_title never raises even if stdout fails."""
        with patch.object(sys, "stdout", None):
            # Should not raise
            set_terminal_title("Safe Title")


class TestTerminalSize:
    def test_get_terminal_size_dimensions(self):
        """Verify get_terminal_size returns positive dimensions."""
        cols, lines = get_terminal_size()
        assert isinstance(cols, int)
        assert isinstance(lines, int)
        assert cols > 0
        assert lines > 0

    def test_get_terminal_size_custom_fallback(self):
        """Verify custom fallback is used when console has no size and shutil fails."""
        with patch("siyarix.chat.console.console") as mock_console:
            mock_console.size = None
            with patch("shutil.get_terminal_size", side_effect=Exception("no term")):
                cols, lines = get_terminal_size(fallback=(120, 40))
                assert cols == 120
                assert lines == 40


# ---------------------------------------------------------------------------
# Bottom Toolbar & Input UX Tests
# ---------------------------------------------------------------------------


class TestBottomToolbar:
    def test_make_bottom_toolbar_integrated(self):
        """Verify bottom toolbar renders mode, provider, and msgs."""
        toolbar = make_bottom_toolbar(
            mode="integrated",
            provider="gemini",
            session_id="abcdef123456",
            msg_count=5,
            target="",
            multiline=False,
        )
        assert isinstance(toolbar, FormattedText)
        text_content = "".join(text for _, text in toolbar)
        assert "siyarix" in text_content
        assert "[integrated]" in text_content
        assert "gemini" in text_content
        assert "sid:abcdef" in text_content
        assert "msgs:5" in text_content
        assert "[ML: OFF]" in text_content

    def test_make_bottom_toolbar_multiline_on(self):
        """Verify multiline indicator shows [ML: ON] when enabled."""
        toolbar = make_bottom_toolbar(
            mode="autonomous",
            provider="openai",
            session_id="998877",
            msg_count=12,
            target="192.168.1.100",
            multiline=True,
        )
        assert isinstance(toolbar, FormattedText)
        text_content = "".join(text for _, text in toolbar)
        assert "[autonomous]" in text_content
        assert "target:" in text_content
        assert "192.168.1.100" in text_content
        assert "[ML: ON]" in text_content

    def test_make_bottom_toolbar_modes_colors(self):
        """Verify various modes map to valid ANSI styles."""
        modes = ["redteam", "blueteam", "stealth", "compliance", "offline"]
        for m in modes:
            toolbar = make_bottom_toolbar(mode=m)
            assert isinstance(toolbar, FormattedText)
            text_content = "".join(text for _, text in toolbar)
            assert f"[{m}]" in text_content


# ---------------------------------------------------------------------------
# Output Systems & Paging Tests
# ---------------------------------------------------------------------------


class TestPrintPaged:
    def test_print_paged_non_terminal_prints_directly(self):
        """When not attached to a terminal, print_paged prints directly without pager."""
        mock_console = MagicMock(spec=Console)
        mock_console.is_terminal = False

        print_paged("Hello World", console_instance=mock_console, force=False)
        mock_console.print.assert_called_once_with("Hello World")
        mock_console.pager.assert_not_called()

    def test_print_paged_within_height_prints_directly(self):
        """When rendered lines <= terminal height, print directly."""
        mock_console = MagicMock(spec=Console)
        mock_console.is_terminal = True
        mock_console.size.height = 25

        mock_capture = MagicMock()
        mock_capture.get.return_value = "Line 1\nLine 2\nLine 3\n"
        mock_console.capture.return_value.__enter__.return_value = mock_capture

        print_paged("Short text", console_instance=mock_console, force=False)
        mock_console.pager.assert_not_called()
        assert mock_console.print.call_count >= 1

    def test_print_paged_exceeds_height_uses_pager(self):
        """When rendered lines > terminal height and is_terminal=True, pager is invoked."""
        mock_console = MagicMock(spec=Console)
        mock_console.is_terminal = True
        mock_console.size.height = 10

        mock_capture = MagicMock()
        mock_capture.get.return_value = "\n".join(f"Line {i}" for i in range(50))
        mock_console.capture.return_value.__enter__.return_value = mock_capture

        print_paged("Long text", console_instance=mock_console, force=False)
        mock_console.pager.assert_called_once_with(styles=True)

    def test_print_paged_force_flag_invokes_pager(self):
        """When force=True and is_terminal=True, pager is invoked regardless of height."""
        mock_console = MagicMock(spec=Console)
        mock_console.is_terminal = True
        mock_console.size.height = 50

        print_paged("Forced pager text", console_instance=mock_console, force=True)
        mock_console.pager.assert_called_once_with(styles=True)


class TestOutputEnginePaged:
    def test_output_engine_print_paged_no_rich(self):
        """Verify OutputEngine raw print fallback when console is None."""
        engine = OutputEngine()
        engine.console = None
        with patch.object(engine, "_raw_print") as mock_raw:
            engine.print_paged("Test Content")
            mock_raw.assert_called_once_with("Test Content")

    def test_output_engine_print_table_page_force(self):
        """Verify print_table with page=True calls print_paged with force=True."""
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.format = OutputFormat.TABLE
        with patch.object(engine, "print_paged") as mock_paged:
            data = [{"col1": "val1", "col2": "val2"}]
            engine.print_table(data, title="Paged Table", page=True)
            mock_paged.assert_called_once()
            _, kwargs = mock_paged.call_args
            assert kwargs.get("force") is True

    def test_output_engine_print_table_default(self):
        """Verify print_table without page=True prints table to console."""
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.format = OutputFormat.TABLE
        data = [{"col1": "val1", "col2": "val2"}]
        engine.print_table(data, title="Standard Table", page=False)
        engine.console.print.assert_called_once()


# ---------------------------------------------------------------------------
# REPL Input & Raw Terminal Handling Tests
# ---------------------------------------------------------------------------


class TestReplInputHandling:
    def test_repl_terminal_supports_raw_non_tty(self):
        """Verify _terminal_supports_raw returns False when stdin is not a TTY."""
        chat = SiyarixChat()
        with patch.object(sys.stdin, "isatty", return_value=False):
            assert chat._terminal_supports_raw() is False

    def test_repl_multiline_toggle(self):
        """Verify toggling _multiline updates the property."""
        chat = SiyarixChat()
        initial = chat._multiline
        chat._multiline = not initial
        assert chat._multiline != initial
