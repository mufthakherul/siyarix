"""Tests for progress.py — ScanProgressDisplay / CancellationToken (165 stmts, 48%)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from siyarix.progress import (
    CancellationToken,
    ScanProgressDisplay,
    ScanProgressState,
    run_tools_with_progress,
)


# ---------------------------------------------------------------------------
# ScanProgressState
# ---------------------------------------------------------------------------

class TestScanProgressState:
    def test_init(self):
        s = ScanProgressState(tools_total=3)
        assert s.tools_total == 3
        assert s.tools_done == 0
        assert s.current_tools == []
        assert s.finding_counts == {}
        assert s.cancelled is False
        assert s.cancel_all is False

    def test_elapsed(self):
        s = ScanProgressState()
        assert s.elapsed >= 0.0

    def test_total_findings(self):
        s = ScanProgressState()
        s.finding_counts = {"high": 3, "low": 2}
        assert s.total_findings == 5

    def test_add_finding(self):
        s = ScanProgressState()
        s.add_finding("critical")
        s.add_finding("critical")
        s.add_finding("low")
        assert s.finding_counts == {"critical": 2, "low": 1}

    def test_add_finding_case_insensitive(self):
        s = ScanProgressState()
        s.add_finding("HIGH")
        assert s.finding_counts["high"] == 1


# ---------------------------------------------------------------------------
# ScanProgressDisplay
# ---------------------------------------------------------------------------

class TestScanProgressDisplay:
    @pytest.fixture
    def state(self):
        return ScanProgressState(tools_total=2)

    def test_context_manager(self, state):
        display = ScanProgressDisplay(state)
        display._live = MagicMock()
        with patch.object(display._live, "__enter__", return_value=display._live), \
             patch.object(display._live, "__exit__", return_value=None):
            with display as d:
                assert d is display
                assert display._overall_task is not None

    def test_context_manager_direct(self, state):
        with patch("siyarix.progress.Live") as MockLive:
            mock_live = MockLive.return_value
            display = ScanProgressDisplay(state)
            display._live = MagicMock()
            display.__enter__()
            # __enter__ creates a new Live, so display._live is now a Live instance
            display.__exit__(None, None, None)
            mock_live.__exit__.assert_called()

    def test_tool_started(self, state):
        display = ScanProgressDisplay(state)
        display._live = MagicMock()
        display.tool_started("nmap")
        assert "nmap" in display._state._task_ids

    def test_tool_done(self, state):
        display = ScanProgressDisplay(state)
        display._live = MagicMock()
        display.tool_started("nmap")
        display.tool_done("nmap", 5)
        assert state.tools_done == 1

    def test_tool_done_no_task_id(self, state):
        display = ScanProgressDisplay(state)
        display._live = MagicMock()
        display.tool_done("nonexistent", 0)
        assert state.tools_done == 1

    def test_tool_error(self, state):
        display = ScanProgressDisplay(state)
        display._live = MagicMock()
        display.tool_started("nmap")
        display.tool_error("nmap", "connection timeout")
        assert state.tools_done == 1

    def test_refresh(self, state):
        display = ScanProgressDisplay(state)
        display._live = MagicMock()
        display.refresh()
        display._live.update.assert_called()

    def test_refresh_no_live(self, state):
        display = ScanProgressDisplay(state)
        display._live = None
        display.refresh()

    def test_render(self, state):
        display = ScanProgressDisplay(state)
        group = display._render()
        assert group is not None

    def test_render_with_findings(self, state):
        state.add_finding("critical")
        state.add_finding("high")
        display = ScanProgressDisplay(state)
        group = display._render()
        assert group is not None

    def test_render_findings_summary(self, state):
        state.add_finding("critical")
        state.add_finding("medium")
        display = ScanProgressDisplay(state)
        table = display._render_findings_summary()
        assert table is not None

    def test_print_summary(self, state):
        display = ScanProgressDisplay(state)
        state.tools_done = 1
        state.tools_total = 2
        state.add_finding("high")
        with patch.object(display._console, "print") as mp:
            display.print_summary("10.0.0.1")
            mp.assert_called_once()

    def test_print_summary_no_findings(self, state):
        display = ScanProgressDisplay(state)
        state.tools_done = 2
        state.tools_total = 2
        with patch.object(display._console, "print") as mp:
            display.print_summary("clean-target")
            mp.assert_called_once()


# ---------------------------------------------------------------------------
# CancellationToken
# ---------------------------------------------------------------------------

class TestCancellationToken:
    def test_initial_state(self):
        t = CancellationToken()
        assert t.cancel_current is False
        assert t.cancel_all is False

    def test_first_sigint(self):
        t = CancellationToken()
        t._handle_sigint()
        assert t.cancel_current is True
        assert t.cancel_all is False

    def test_second_sigint_within_2s(self):
        t = CancellationToken()
        t._handle_sigint()
        t._last_press = time.monotonic()  # ensure recent
        t._handle_sigint()
        assert t.cancel_all is True

    def test_second_sigint_after_2s(self):
        t = CancellationToken()
        t._handle_sigint()
        t._last_press = time.monotonic() - 3.0  # older than 2s
        t._handle_sigint()
        # Resets to 1 (not 2) since timeout elapsed
        assert t._press_count == 1
        assert t.cancel_all is False
        assert t.cancel_current is True

    def test_install_and_uninstall(self):
        import signal
        t = CancellationToken()
        t.install()
        assert signal.getsignal(signal.SIGINT) == t._handle_sigint
        t.uninstall()
        assert signal.getsignal(signal.SIGINT) == signal.SIG_DFL


# ---------------------------------------------------------------------------
# run_tools_with_progress
# ---------------------------------------------------------------------------

class TestRunToolsWithProgress:
    @pytest.mark.asyncio
    async def test_empty_tools(self):
        tools = []
        with patch("siyarix.progress.CancellationToken.install"), \
             patch("siyarix.progress.CancellationToken.uninstall"), \
             patch("siyarix.progress.ScanProgressDisplay"):
            results, state = await run_tools_with_progress(
                tools, "10.0.0.1", max_parallel=2
            )
            assert results == []
            assert state.tools_total == 0

    @pytest.mark.asyncio
    async def test_run_one_tool(self):
        tools = [{"name": "nmap", "path": "/usr/bin/nmap", "args": ["-sV"]}]
        with patch("siyarix.executor.run_tool_complete") as mock_run, \
             patch("siyarix.progress.CancellationToken.install"), \
             patch("siyarix.progress.CancellationToken.uninstall"), \
             patch("siyarix.progress.ScanProgressDisplay"):
            mock_result = MagicMock()
            mock_result.exit_code = 0
            mock_result.stdout = "mock output"
            mock_run.return_value = mock_result
            results, state = await run_tools_with_progress(
                tools, "10.0.0.1", max_parallel=2
            )
            assert len(results) == 1

    @pytest.mark.asyncio
    async def test_run_tool_exception(self):
        tools = [{"name": "nmap", "path": "/usr/bin/nmap", "args": ["-sV"]}]
        with patch("siyarix.executor.run_tool_complete",
                   side_effect=RuntimeError("tool failed")), \
             patch("siyarix.progress.CancellationToken.install"), \
             patch("siyarix.progress.CancellationToken.uninstall"), \
             patch("siyarix.progress.ScanProgressDisplay"):
            results, state = await run_tools_with_progress(
                tools, "10.0.0.1", max_parallel=2
            )
            assert len(results) == 1
            assert results[0]["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_run_tool_cancelled_all(self):
        tools = [{"name": "nmap", "path": "/usr/bin/nmap", "args": ["-sV"]}]
        with patch("siyarix.progress.CancellationToken") as MockToken, \
             patch("siyarix.progress.CancellationToken.install"), \
             patch("siyarix.progress.CancellationToken.uninstall"), \
             patch("siyarix.progress.ScanProgressDisplay"):
            token = MockToken
            token.cancel_all = True
            token.cancel_current = False
            results, state = await run_tools_with_progress(
                tools, "10.0.0.1", max_parallel=2
            )
