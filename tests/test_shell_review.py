# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.shell_review — shell injection review loop."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from siyarix.shell_review import (
    PREAUTHORIZED_ENV_VAR,
    ReviewDecision,
    ReviewResult,
    is_preauthorized,
    review_and_confirm,
    review_command,
    review_refusal_message,
)


class TestReviewDecision:
    def test_constants(self) -> None:
        assert ReviewDecision.EDIT == "edit"
        assert ReviewDecision.RUN == "run"
        assert ReviewDecision.STEP == "step"
        assert ReviewDecision.CANCEL == "cancel"


class TestReviewResult:
    def test_defaults(self) -> None:
        r = ReviewResult(decision="run")
        assert r.decision == "run"
        assert r.edited_command == ""


class TestReviewCommand:
    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.console")
    @patch("siyarix.shell_review.Prompt.ask", return_value="run")
    def test_run_choice(
        self,
        mock_ask: MagicMock,
        mock_console: MagicMock,
        mock_stdout: MagicMock,
        mock_stdin: MagicMock,
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        result = review_command("ls -la", "shell", "review needed")
        assert result.decision == ReviewDecision.RUN
        assert result.edited_command == "ls -la"

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.console")
    @patch("siyarix.shell_review.Prompt.ask")
    def test_edit_choice(
        self,
        mock_ask: MagicMock,
        mock_console: MagicMock,
        mock_stdout: MagicMock,
        mock_stdin: MagicMock,
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        mock_ask.side_effect = ["edit", "ls -Al"]
        result = review_command("ls -la", "shell", "review needed")
        assert result.decision == ReviewDecision.EDIT
        assert result.edited_command == "ls -Al"

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.console")
    @patch("siyarix.shell_review.Prompt.ask", return_value="step")
    def test_step_choice(
        self,
        mock_ask: MagicMock,
        mock_console: MagicMock,
        mock_stdout: MagicMock,
        mock_stdin: MagicMock,
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        result = review_command("ls -la", "shell", "review needed")
        assert result.decision == ReviewDecision.STEP
        assert result.edited_command == "ls -la"

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.console")
    @patch("siyarix.shell_review.Prompt.ask", return_value="cancel")
    def test_cancel_choice(
        self,
        mock_ask: MagicMock,
        mock_console: MagicMock,
        mock_stdout: MagicMock,
        mock_stdin: MagicMock,
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        result = review_command("ls -la", "shell", "review needed")
        assert result.decision == ReviewDecision.CANCEL
        assert result.edited_command == ""

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.console")
    @patch("siyarix.shell_review.Prompt.ask", return_value="run")
    def test_displays_panel(
        self,
        mock_ask: MagicMock,
        mock_console: MagicMock,
        mock_stdout: MagicMock,
        mock_stdin: MagicMock,
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        review_command("echo test", "test_tool", "dangerous command")
        mock_console.print.assert_called_once()


class TestReviewAndConfirm:
    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.review_command")
    def test_cancel_returns_none(
        self, mock_review: MagicMock, mock_stdout: MagicMock, mock_stdin: MagicMock
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        mock_review.return_value = ReviewResult(decision=ReviewDecision.CANCEL, edited_command="")
        result = review_and_confirm("rm -rf /", "shell", "destructive")
        assert result is None

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.review_command")
    def test_edit_returns_edited(
        self, mock_review: MagicMock, mock_stdout: MagicMock, mock_stdin: MagicMock
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        mock_review.return_value = ReviewResult(
            decision=ReviewDecision.EDIT, edited_command="ls -la"
        )
        result = review_and_confirm("rm -rf /", "shell", "destructive")
        assert result == "ls -la"

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.review_command")
    def test_run_returns_original(
        self, mock_review: MagicMock, mock_stdout: MagicMock, mock_stdin: MagicMock
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        mock_review.return_value = ReviewResult(
            decision=ReviewDecision.RUN, edited_command="rm -rf /"
        )
        result = review_and_confirm("rm -rf /", "shell", "destructive")
        assert result == "rm -rf /"

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    @patch("siyarix.shell_review.review_command")
    def test_step_returns_original(
        self, mock_review: MagicMock, mock_stdout: MagicMock, mock_stdin: MagicMock
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        mock_review.return_value = ReviewResult(
            decision=ReviewDecision.STEP, edited_command="rm -rf /"
        )
        result = review_and_confirm("rm -rf /", "shell", "destructive")
        assert result == "rm -rf /"

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    def test_noninteractive_fails_closed(
        self, mock_stdout: MagicMock, mock_stdin: MagicMock, monkeypatch
    ) -> None:
        mock_stdin.isatty.return_value = False
        mock_stdout.isatty.return_value = False
        monkeypatch.delenv(PREAUTHORIZED_ENV_VAR, raising=False)
        assert review_and_confirm("echo audit", "shell", "needs review") is None
        result = review_command("echo audit", "shell", "needs review")
        assert result.decision == ReviewDecision.CANCEL

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    def test_noninteractive_preauthorized_allows(
        self, mock_stdout: MagicMock, mock_stdin: MagicMock, monkeypatch
    ) -> None:
        mock_stdin.isatty.return_value = False
        mock_stdout.isatty.return_value = False
        monkeypatch.setenv(PREAUTHORIZED_ENV_VAR, "1")
        assert review_and_confirm("echo audit", "shell", "needs review") == "echo audit"
        result = review_command("echo audit", "shell", "needs review")
        assert result.decision == ReviewDecision.RUN

    def test_is_preauthorized_reads_env(self, monkeypatch) -> None:
        monkeypatch.setenv(PREAUTHORIZED_ENV_VAR, "true")
        assert is_preauthorized() is True
        monkeypatch.setenv(PREAUTHORIZED_ENV_VAR, "0")
        assert is_preauthorized() is False
        monkeypatch.delenv(PREAUTHORIZED_ENV_VAR, raising=False)
        assert is_preauthorized() is False

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    def test_refusal_message_non_tty_guidance(
        self, mock_stdout: MagicMock, mock_stdin: MagicMock
    ) -> None:
        mock_stdin.isatty.return_value = False
        mock_stdout.isatty.return_value = False
        msg = review_refusal_message("needs review")
        assert "Cancelled by user" not in msg
        assert PREAUTHORIZED_ENV_VAR in msg

    @patch("siyarix.shell_review.sys.stdin")
    @patch("siyarix.shell_review.sys.stdout")
    def test_refusal_message_interactive_cancel(
        self, mock_stdout: MagicMock, mock_stdin: MagicMock
    ) -> None:
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        assert review_refusal_message("needs review") == "Cancelled by user: needs review"
