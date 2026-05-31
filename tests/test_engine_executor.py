# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for executor.py — v2 Executor class."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.executor import ExecutionBudget, Executor, GuardrailConfig, ToolCallTracker
from siyarix.planner import (
    ExecutionPlan,
    PlanStatus,
    PlanStep,
    PlanType,
    StepStatus,
)
from siyarix.registry import ToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_step(
    step_id: str = "s1",
    tool: str = "nmap",
    args: dict | None = None,
    dependencies: list[str] | None = None,
    status: StepStatus = StepStatus.PENDING,
) -> PlanStep:
    return PlanStep(
        id=step_id,
        tool=tool,
        args=args or {},
        dependencies=dependencies or [],
        status=status,
    )


def make_plan(
    steps: list[PlanStep] | None = None,
    plan_type: PlanType = PlanType.SEQUENTIAL,
    goal: str = "test goal",
) -> ExecutionPlan:
    return ExecutionPlan(
        goal=goal,
        plan_type=plan_type,
        steps=steps or [],
    )


def ok_executor(step: PlanStep) -> dict:
    return {"status": "success", "output": f"done:{step.tool}"}


def fail_executor(step: PlanStep) -> dict:
    return {"status": "error", "error": f"fail:{step.tool}"}


def make_async_executor(return_val: dict | None = None):
    val = return_val or {"status": "success"}
    return AsyncMock(return_value=val)


# ---------------------------------------------------------------------------
# TestExecutorInit
# ---------------------------------------------------------------------------

class TestExecutorInit:
    def test_default_budget(self):
        ex = Executor()
        assert ex.budget.max_iterations == 50
        assert ex.budget.max_tool_calls == 100

    def test_default_stats(self):
        ex = Executor()
        s = ex.stats()
        assert s["budget"]["iterations"] == 0
        assert s["budget"]["tool_calls"] == 0
        assert "elapsed_s" in s["budget"]
        assert s["tracker"]["failures"] == {}
        assert s["tracker"]["no_progress"] == 0

    def test_registry_stored(self):
        reg = MagicMock(spec=ToolRegistry)
        ex = Executor(registry=reg)
        assert ex._registry is reg

    def test_no_registry(self):
        ex = Executor()
        assert ex._registry is None

    def test_custom_executors_empty(self):
        ex = Executor()
        assert ex._custom_executors == {}

    def test_register_executor(self):
        ex = Executor()
        fn = AsyncMock()
        ex.register_executor("nmap", fn)
        assert "nmap" in ex._custom_executors
        assert ex._custom_executors["nmap"] is fn


# ---------------------------------------------------------------------------
# TestExecutePlan
# ---------------------------------------------------------------------------

class TestExecutePlan:
    @pytest.mark.asyncio
    async def test_sequential_execution(self):
        s1 = make_step("s1", tool="nmap")
        s2 = make_step("s2", tool="nuclei", dependencies=["s1"])
        plan = make_plan(steps=[s1, s2], plan_type=PlanType.SEQUENTIAL)
        ex = Executor()
        executor_fn = make_async_executor({"status": "success"})
        result = await ex.execute_plan(plan, executor_fn)
        assert result.status == PlanStatus.COMPLETED
        assert s1.status == StepStatus.COMPLETED
        assert s2.status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_parallel_execution(self):
        s1 = make_step("s1", tool="nmap")
        s2 = make_step("s2", tool="nuclei")
        plan = make_plan(steps=[s1, s2], plan_type=PlanType.PARALLEL)
        ex = Executor()
        executor_fn = make_async_executor({"status": "success"})
        result = await ex.execute_plan(plan, executor_fn)
        assert result.status == PlanStatus.COMPLETED
        assert s1.status == StepStatus.COMPLETED
        assert s2.status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_empty_plan(self):
        plan = make_plan(steps=[], plan_type=PlanType.SEQUENTIAL)
        ex = Executor()
        result = await ex.execute_plan(plan, make_async_executor())
        assert result.status == PlanStatus.COMPLETED
        assert result.progress_pct == 100.0

    @pytest.mark.asyncio
    async def test_plan_sets_active(self):
        plan = make_plan(steps=[make_step("s1")], plan_type=PlanType.SEQUENTIAL)
        ex = Executor()
        await ex.execute_plan(plan, make_async_executor())
        assert plan.status in (PlanStatus.COMPLETED, PlanStatus.FAILED)

    @pytest.mark.asyncio
    async def test_plan_status_failed_on_step_failure(self):
        s1 = make_step("s1", tool="nmap")
        plan = make_plan(steps=[s1], plan_type=PlanType.SEQUENTIAL)
        ex = Executor()
        result = await ex.execute_plan(plan, fail_executor)
        assert result.status == PlanStatus.FAILED
        assert s1.status == StepStatus.FAILED

    @pytest.mark.asyncio
    async def test_dag_plan_runs_parallel(self):
        s1 = make_step("s1", tool="nmap")
        s2 = make_step("s2", tool="nuclei")
        plan = make_plan(steps=[s1, s2], plan_type=PlanType.DAG)
        ex = Executor()
        result = await ex.execute_plan(plan, make_async_executor())
        assert result.status == PlanStatus.COMPLETED
        assert s1.status == StepStatus.COMPLETED
        assert s2.status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_dependency_blocks_step(self):
        s1 = make_step("s1", tool="nmap", dependencies=["missing"])
        plan = make_plan(steps=[s1], plan_type=PlanType.SEQUENTIAL)
        ex = Executor()
        result = await ex.execute_plan(plan, make_async_executor())
        assert s1.status == StepStatus.PENDING

    @pytest.mark.asyncio
    async def test_dependency_chain_resolves(self):
        s1 = make_step("s1", tool="nmap")
        s2 = make_step("s2", tool="nuclei", dependencies=["s1"])
        plan = make_plan(steps=[s1, s2], plan_type=PlanType.SEQUENTIAL)
        ex = Executor()
        result = await ex.execute_plan(plan, make_async_executor())
        assert s2.status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_failed_dependency_blocks_downstream(self):
        s1 = make_step("s1", tool="nmap")
        s2 = make_step("s2", tool="nuclei", dependencies=["s1"])
        plan = make_plan(steps=[s1, s2], plan_type=PlanType.SEQUENTIAL)
        ex = Executor()
        result = await ex.execute_plan(plan, fail_executor)
        assert s1.status == StepStatus.FAILED
        assert s2.status == StepStatus.PENDING

    @pytest.mark.asyncio
    async def test_no_executor_fn_uses_registry(self):
        s1 = make_step("s1", tool="nmap")
        plan = make_plan(steps=[s1])
        reg = MagicMock(spec=ToolRegistry)
        reg.execute = AsyncMock(return_value={"status": "success"})
        ex = Executor(registry=reg)
        result = await ex.execute_plan(plan)
        reg.execute.assert_called_once_with("nmap")

    @pytest.mark.asyncio
    async def test_no_registry_no_executor_sets_error(self):
        s1 = make_step("s1", tool="nmap")
        plan = make_plan(steps=[s1])
        ex = Executor()
        result = await ex.execute_plan(plan)
        assert s1.status == StepStatus.FAILED
        assert "No executor" in s1.result.get("error", "")

    @pytest.mark.asyncio
    async def test_custom_executor_overrides_registry(self):
        s1 = make_step("s1", tool="nmap")
        plan = make_plan(steps=[s1])
        reg = MagicMock(spec=ToolRegistry)
        reg.execute = AsyncMock()
        ex = Executor(registry=reg)
        custom = make_async_executor({"status": "success", "output": "custom"})
        ex.register_executor("nmap", custom)
        result = await ex.execute_plan(plan)
        custom.assert_called_once()
        reg.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_executor_fn_overrides_custom(self):
        s1 = make_step("s1", tool="nmap")
        plan = make_plan(steps=[s1])
        ex = Executor()
        custom = AsyncMock(return_value={"status": "success", "output": "custom"})
        ex.register_executor("nmap", custom)
        executor_fn = make_async_executor({"status": "success", "output": "fn"})
        result = await ex.execute_plan(plan, executor_fn)
        assert s1.result.get("output") == "fn"
        custom.assert_not_called()


# ---------------------------------------------------------------------------
# TestExecuteStep
# ---------------------------------------------------------------------------

class TestExecuteStep:
    @pytest.mark.asyncio
    async def test_success(self):
        s1 = make_step("s1", tool="nmap")
        ex = Executor()
        executor_fn = make_async_executor({"status": "success", "output": "ok"})
        await ex._execute_step(s1, executor_fn)
        assert s1.status == StepStatus.COMPLETED
        assert s1.result.get("output") == "ok"
        assert s1.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_failure(self):
        s1 = make_step("s1", tool="nmap")
        ex = Executor()
        executor_fn = make_async_executor({"status": "error", "error": "bad"})
        await ex._execute_step(s1, executor_fn)
        assert s1.status == StepStatus.FAILED
        assert "bad" in s1.result.get("error", "")

    @pytest.mark.asyncio
    async def test_timeout_cancelled(self):
        s1 = make_step("s1", tool="nmap")
        ex = Executor()

        async def slow_executor(step):
            await asyncio.sleep(100)
            return {"status": "success"}

        task = asyncio.create_task(ex._execute_step(s1, slow_executor))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert s1.status == StepStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_exception_sets_failed(self):
        s1 = make_step("s1", tool="nmap")
        ex = Executor()

        async def bad_executor(step):
            raise RuntimeError("boom")

        await ex._execute_step(s1, bad_executor)
        assert s1.status == StepStatus.FAILED
        assert "boom" in s1.result.get("error", "")

    @pytest.mark.asyncio
    async def test_duration_recorded(self):
        s1 = make_step("s1", tool="nmap")
        ex = Executor()
        await ex._execute_step(s1, make_async_executor())
        assert s1.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_step_result_stored(self):
        s1 = make_step("s1", tool="nmap")
        ex = Executor()
        await ex._execute_step(s1, make_async_executor({"status": "success", "x": 1}))
        assert s1.result == {"status": "success", "x": 1}


# ---------------------------------------------------------------------------
# TestBudget
# ---------------------------------------------------------------------------

class TestBudget:
    def test_iteration_limit(self):
        b = ExecutionBudget(max_iterations=3)
        assert b.consume_iteration() is True
        assert b.consume_iteration() is True
        assert b.consume_iteration() is True
        assert b.consume_iteration() is False
        assert b.is_exhausted is True

    def test_tool_call_limit(self):
        b = ExecutionBudget(max_tool_calls=2)
        assert b.consume_tool_call() is True
        assert b.consume_tool_call() is True
        assert b.consume_tool_call() is False

    def test_remaining_iterations(self):
        b = ExecutionBudget(max_iterations=5)
        b.consume_iteration()
        b.consume_iteration()
        assert b.remaining_iterations == 3

    def test_remaining_tool_calls(self):
        b = ExecutionBudget(max_tool_calls=10)
        b.consume_tool_call()
        assert b.remaining_tool_calls == 9

    @pytest.mark.asyncio
    async def test_budget_stops_execution(self):
        b = ExecutionBudget(max_iterations=1)
        s1 = make_step("s1", tool="nmap")
        s2 = make_step("s2", tool="nuclei")
        plan = make_plan(steps=[s1, s2])
        ex = Executor()
        ex._budget = b
        await ex.execute_plan(plan, make_async_executor())
        assert s1.status == StepStatus.COMPLETED
        assert s2.status != StepStatus.COMPLETED

    def test_budget_no_progress_on_exhausted(self):
        b = ExecutionBudget(max_iterations=0)
        assert b.consume_iteration() is False
        b2 = ExecutionBudget(max_tool_calls=0)
        assert b2.consume_tool_call() is False

    def test_is_exhausted_by_iterations(self):
        b = ExecutionBudget(max_iterations=2)
        b.consume_iteration()
        b.consume_iteration()
        assert b.is_exhausted is True

    def test_is_exhausted_by_tool_calls(self):
        b = ExecutionBudget(max_tool_calls=2)
        b.consume_tool_call()
        b.consume_tool_call()
        assert b.is_exhausted is True


# ---------------------------------------------------------------------------
# TestGuardrails
# ---------------------------------------------------------------------------

class TestGuardrails:
    def test_exact_failure_blocks(self):
        cfg = GuardrailConfig(exact_failure_block_after=3)
        tracker = ToolCallTracker(cfg)
        assert tracker.record("nmap", "args1", False) is None
        assert tracker.record("nmap", "args1", False) is None
        result = tracker.record("nmap", "args1", False)
        assert result is not None
        assert "BLOCKED" in result

    def test_same_tool_consecutive_halts(self):
        cfg = GuardrailConfig(same_tool_failure_halt_after=3)
        tracker = ToolCallTracker(cfg)
        tracker.record("nmap", "a", False)
        tracker.record("nmap", "b", False)
        result = tracker.record("nmap", "c", False)
        assert result is not None
        assert "HALTED" in result

    def test_no_progress_blocks(self):
        cfg = GuardrailConfig(no_progress_block_after=3)
        tracker = ToolCallTracker(cfg)
        tracker.record("nmap", "same_args", True)
        tracker.record("nmap", "same_args", False)
        tracker.record("nmap", "same_args", False)
        result = tracker.record("nmap", "same_args", False)
        assert result is not None
        assert "No progress" in result

    def test_success_resets_counters(self):
        cfg = GuardrailConfig(exact_failure_block_after=3)
        tracker = ToolCallTracker(cfg)
        tracker.record("nmap", "a", False)
        tracker.record("nmap", "a", False)
        tracker.record("nmap", "a", True)
        result = tracker.record("nmap", "a", False)
        assert result is None

    def test_success_resets_consecutive(self):
        cfg = GuardrailConfig(same_tool_failure_halt_after=3)
        tracker = ToolCallTracker(cfg)
        tracker.record("nmap", "a", False)
        tracker.record("nmap", "a", False)
        tracker.record("nmap", "a", True)
        result = tracker.record("nmap", "a", False)
        assert result is None

    def test_different_tools_independent(self):
        cfg = GuardrailConfig(exact_failure_block_after=2)
        tracker = ToolCallTracker(cfg)
        tracker.record("nmap", "a", False)
        tracker.record("nmap", "a", False)
        result_nmap = tracker.record("nmap", "a", False)
        assert result_nmap is not None
        result_nuclei = tracker.record("nuclei", "a", False)
        assert result_nuclei is None

    def test_tracker_reset(self):
        tracker = ToolCallTracker()
        tracker.record("nmap", "a", False)
        tracker.record("nmap", "a", False)
        tracker.reset()
        result = tracker.record("nmap", "a", False)
        assert result is None

    def test_guardrail_blocks_in_execute_step(self):
        cfg = GuardrailConfig(exact_failure_block_after=1)
        tracker = ToolCallTracker(cfg)
        tracker.record("nmap", "args", False)
        result = tracker.record("nmap", "args", False)
        assert result is not None
        assert "BLOCKED" in result

    def test_no_progress_only_on_same_args(self):
        cfg = GuardrailConfig(no_progress_block_after=3)
        tracker = ToolCallTracker(cfg)
        tracker.record("nmap", "args_a", True)
        tracker.record("nmap", "args_a", False)
        tracker.record("nmap", "args_b", False)
        tracker.record("nmap", "args_c", False)
        assert tracker._no_progress_count == 1


# ---------------------------------------------------------------------------
# TestReset
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_clears_budget(self):
        ex = Executor()
        ex._budget.consume_iteration()
        ex._budget.consume_tool_call()
        ex.reset()
        assert ex._budget._iterations == 0
        assert ex._budget._tool_calls == 0

    def test_reset_clears_tracker(self):
        ex = Executor()
        ex._tracker.record("nmap", "a", False)
        ex._tracker.record("nmap", "a", False)
        ex.reset()
        s = ex.stats()
        assert s["tracker"]["failures"] == {}
        assert s["tracker"]["no_progress"] == 0

    def test_reset_allows_reuse(self):
        ex = Executor()
        b = ExecutionBudget(max_iterations=1)
        ex._budget = b
        ex._budget.consume_iteration()
        assert ex._budget.is_exhausted is True
        ex.reset()
        assert ex._budget.is_exhausted is False


# ---------------------------------------------------------------------------
# TestStats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_structure(self):
        ex = Executor()
        s = ex.stats()
        assert "budget" in s
        assert "tracker" in s
        assert "iterations" in s["budget"]
        assert "tool_calls" in s["budget"]
        assert "elapsed_s" in s["budget"]
        assert "failures" in s["tracker"]
        assert "no_progress" in s["tracker"]

    def test_stats_reflects_budget(self):
        ex = Executor()
        ex._budget.consume_iteration()
        ex._budget.consume_iteration()
        ex._budget.consume_tool_call()
        s = ex.stats()
        assert s["budget"]["iterations"] == 2
        assert s["budget"]["tool_calls"] == 1

    def test_stats_reflects_tracker(self):
        ex = Executor()
        ex._tracker.record("nmap", "a", False)
        ex._tracker.record("nmap", "a", False)
        s = ex.stats()
        assert s["tracker"]["failures"]["nmap"] == 2

    def test_stats_after_reset(self):
        ex = Executor()
        ex._budget.consume_iteration()
        ex._tracker.record("nmap", "a", False)
        ex.reset()
        s = ex.stats()
        assert s["budget"]["iterations"] == 0
        assert s["tracker"]["failures"] == {}


# ---------------------------------------------------------------------------
# TestEventEmission
# ---------------------------------------------------------------------------

class TestEventEmission:
    @pytest.mark.asyncio
    async def test_plan_created_event(self):
        from siyarix.events import EventType, get_event_bus

        bus = get_event_bus()
        events = []

        async def capture(event):
            events.append(event)

        bus.on(EventType.PLAN_CREATED, capture)
        try:
            s1 = make_step("s1", tool="nmap")
            plan = make_plan(steps=[s1])
            ex = Executor()
            await ex.execute_plan(plan, make_async_executor())
            assert any(e.type == EventType.PLAN_CREATED for e in events)
        finally:
            bus.off(EventType.PLAN_CREATED, capture)
            bus.clear()

    @pytest.mark.asyncio
    async def test_plan_complete_event(self):
        from siyarix.events import EventType, get_event_bus

        bus = get_event_bus()
        events = []

        async def capture(event):
            events.append(event)

        bus.on(EventType.PLAN_COMPLETE, capture)
        try:
            s1 = make_step("s1", tool="nmap")
            plan = make_plan(steps=[s1])
            ex = Executor()
            await ex.execute_plan(plan, make_async_executor())
            assert any(e.type == EventType.PLAN_COMPLETE for e in events)
        finally:
            bus.off(EventType.PLAN_COMPLETE, capture)
            bus.clear()

    @pytest.mark.asyncio
    async def test_step_events(self):
        from siyarix.events import EventType, get_event_bus

        bus = get_event_bus()
        events = []

        async def capture(event):
            events.append(event)

        bus.on(EventType.PLAN_STEP_START, capture)
        bus.on(EventType.PLAN_STEP_COMPLETE, capture)
        try:
            s1 = make_step("s1", tool="nmap")
            plan = make_plan(steps=[s1])
            ex = Executor()
            await ex.execute_plan(plan, make_async_executor())
            types = [e.type for e in events]
            assert EventType.PLAN_STEP_START in types
            assert EventType.PLAN_STEP_COMPLETE in types
        finally:
            bus.off(EventType.PLAN_STEP_START, capture)
            bus.off(EventType.PLAN_STEP_COMPLETE, capture)
            bus.clear()


# ---------------------------------------------------------------------------
# TestExecutionBudgetDuration
# ---------------------------------------------------------------------------

class TestExecutionBudgetDuration:
    def test_duration_exhaustion(self):
        b = ExecutionBudget(max_iterations=1000, max_tool_calls=1000, max_duration_s=0.0)
        assert b.is_exhausted is True

    def test_elapsed_property(self):
        b = ExecutionBudget()
        assert b.elapsed >= 0.0
