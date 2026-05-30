# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for core/agentic_loop.py — AgenticLoop (112 stmts, ~48% covered)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from siyarix.core.agentic_loop import AgenticLoop


@pytest.fixture
def engine():
    return MagicMock()


@pytest.fixture
def loop(engine):
    return AgenticLoop(engine=engine, goal="test goal", target="10.0.0.1",
                        max_iterations=3, interactive=False)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_defaults(self, engine):
        loop = AgenticLoop(engine=engine, goal="goal")
        assert loop._goal == "goal"
        assert loop._target == ""
        assert loop._max_iterations == 10
        assert loop._interactive is True

    def test_init_custom(self, loop):
        assert loop._goal == "test goal"
        assert loop._target == "10.0.0.1"
        assert loop._max_iterations == 3
        assert loop._interactive is False


# ---------------------------------------------------------------------------
# _observe
# ---------------------------------------------------------------------------

class TestObserve:
    def test_observe_returns_context(self, loop):
        ctx = loop._observe()
        assert ctx["goal"] == "test goal"
        assert ctx["target"] == "10.0.0.1"
        assert ctx["iteration"] == 0
        assert ctx["findings_so_far"] == 0
        assert ctx["recent_observations"] == []


# ---------------------------------------------------------------------------
# _reflect (deferred to v2.0 — currently a no-op)
# ---------------------------------------------------------------------------

class TestReflect:
    def test_reflect_does_nothing(self, loop):
        loop._reflect()
        assert loop._reflection_queue == []


# ---------------------------------------------------------------------------
# _reason
# ---------------------------------------------------------------------------

class TestReason:
    def test_reason_first_iteration(self, loop):
        loop._iteration = 1
        result = loop._reason({"dummy": True})
        assert "test goal" in result
        assert "10.0.0.1" in result

    def test_reason_with_findings(self, loop):
        loop._iteration = 2
        loop._all_findings = [{"severity": "high", "description": "Port 22 open"}]
        result = loop._reason({"dummy": True})
        assert "Findings" in result

    def test_reason_with_errors(self, loop):
        loop._iteration = 2
        loop._observations = [{"error": "timeout"}]
        result = loop._reason({"dummy": True})
        assert "errors" in result.lower()

    def test_reason_no_target(self, loop):
        loop._target = ""
        loop._iteration = 1
        result = loop._reason({})
        assert "on" not in result


# ---------------------------------------------------------------------------
# _evaluate
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_evaluate_success(self, loop):
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.step_results = [MagicMock()]
        mock_result.all_findings = [{"sev": "low"}]
        mock_result.total_duration_ms = 100.0

        loop._evaluate(mock_result)
        assert len(loop._observations) == 1
        assert loop._observations[0]["success"] is True
        assert len(loop._all_findings) == 1

    def test_evaluate_consecutive_failures(self, loop):
        loop._iteration = 3
        for _ in range(3):
            mock_result = MagicMock()
            mock_result.success = False
            mock_result.step_results = []
            mock_result.all_findings = []
            mock_result.total_duration_ms = 0
            loop._evaluate(mock_result)
        assert loop._completed is True


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

class TestRun:
    @pytest.mark.asyncio
    async def test_run_completes(self, loop):
        loop._engine.execute = AsyncMock(return_value=MagicMock(
            success=True, step_results=[], all_findings=[], total_duration_ms=0))
        result = await loop.run()
        assert result["goal"] == "test goal"
        assert result["iterations"] >= 1

    @pytest.mark.asyncio
    async def test_run_from_reflection_queue(self, loop):
        loop._reflection_queue = ["run nmap scan"]
        loop._engine.execute = AsyncMock(return_value=MagicMock(
            success=True, step_results=[], all_findings=[], total_duration_ms=0))
        result = await loop.run()
        assert result["iterations"] >= 1

    @pytest.mark.asyncio
    async def test_run_done_signal(self, loop):
        loop._reflection_queue = ["done"]
        loop._engine.execute = AsyncMock()
        result = await loop.run()
        assert result["completed"] is True

    @pytest.mark.asyncio
    async def test_run_max_iterations(self, loop):
        loop._max_iterations = 0
        loop._engine.execute = AsyncMock()
        result = await loop.run()
        assert result["iterations"] == 0

    @pytest.mark.asyncio
    async def test_run_error_in_execute(self, loop):
        loop._engine.execute = AsyncMock(side_effect=RuntimeError("execution failed"))
        loop._max_iterations = 1
        result = await loop.run()
        assert result["iterations"] == 1
        assert len(result["observations"]) > 0

    @pytest.mark.asyncio
    async def test_run_empty_string_instruction(self, loop):
        loop._reflection_queue = [""]
        loop._engine.execute = AsyncMock()
        result = await loop.run()
        assert result["iterations"] >= 1

    @pytest.mark.asyncio
    async def test_run_finished_signal_variants(self, loop):
        for signal in ["complete", "finished"]:
            loop._reflection_queue = [signal]
            loop._engine.execute = AsyncMock()
            result = await loop.run()
            assert result["completed"] is True
