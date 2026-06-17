from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest
import asyncio
from siyarix.workflow import WorkflowEngine, WorkflowStepStatus, WorkflowStatus

@pytest.mark.asyncio
async def test_workflow_engine_basic():
    engine = WorkflowEngine()
    
    async def dummy_step(args):
        return {"out": args.get("val", 0) + 1}
        
    engine.register_step("dummy", dummy_step)
    
    nodes = [
        {"id": "n1", "step_fn": "dummy", "args": {"val": 1}},
        {"id": "n2", "step_fn": "dummy", "args": {"val": 2}}
    ]
    edges = [{"source": "n1", "target": "n2"}]
    
    wf = engine.create_workflow("test_wf", nodes=nodes, edges=edges)
    assert wf.status == WorkflowStatus.IDLE
    assert len(wf.nodes) == 2
    
    res_wf = await engine.run_workflow(wf)
    
    assert res_wf.status == WorkflowStatus.COMPLETED
    assert res_wf.get_node("n1").status == WorkflowStepStatus.COMPLETED
    assert res_wf.get_node("n1").result == {"out": 2}
    assert res_wf.get_node("n2").status == WorkflowStepStatus.COMPLETED
    assert res_wf.get_node("n2").result == {"out": 3}
    assert res_wf.progress_pct == 100.0

@pytest.mark.asyncio
async def test_workflow_missing_step():
    engine = WorkflowEngine()
    
    wf = engine.create_workflow("test_wf", nodes=[{"id": "n1", "step_fn": "missing"}])
    res_wf = await engine.run_workflow(wf)
    
    assert res_wf.status == WorkflowStatus.FAILED
    assert res_wf.get_node("n1").status == WorkflowStepStatus.FAILED
    assert "No step function" in res_wf.get_node("n1").result["error"]

@pytest.mark.asyncio
async def test_workflow_cancel():
    engine = WorkflowEngine()
    
    async def slow_step(args):
        await asyncio.sleep(0.5)
        return {}
        
    engine.register_step("slow", slow_step)
    wf = engine.create_workflow("test_wf", nodes=[{"id": "n1", "step_fn": "slow"}, {"id": "n2", "step_fn": "slow"}], edges=[{"source": "n1", "target": "n2"}])
    
    task = asyncio.create_task(engine.run_workflow(wf))
    await asyncio.sleep(0.1)
    engine.cancel_workflow(wf.id)
    
    res_wf = await task
    assert res_wf.status == WorkflowStatus.CANCELLED
    assert res_wf.get_node("n2").status == WorkflowStepStatus.SKIPPED

@pytest.mark.asyncio
async def test_workflow_timeout():
    engine = WorkflowEngine()
    
    async def slow_step(args):
        await asyncio.sleep(0.2)
        return {}
        
    engine.register_step("slow", slow_step)
    wf = engine.create_workflow("test_wf", nodes=[{"id": "n1", "step_fn": "slow", "timeout": 0.1}])
    
    res_wf = await engine.run_workflow(wf)
    assert res_wf.status == WorkflowStatus.FAILED
    assert res_wf.get_node("n1").status == WorkflowStepStatus.FAILED
    assert "Timeout after" in res_wf.get_node("n1").result["error"]

def test_workflow_stats():
    engine = WorkflowEngine()
    stats = engine.stats()
    assert stats["total"] == 0
    assert "registered_steps" in stats



"""Extra tests for workflow targeting uncovered lines."""


import asyncio

import pytest

from siyarix.workflow import (
    Workflow,
    WorkflowEngine,
    WorkflowNode,
    WorkflowStatus,
    WorkflowStepStatus,
)


class TestWorkflowModel:
    def test_get_node_returns_none_for_missing(self) -> None:
        wf = Workflow()
        assert wf.get_node("nonexistent") is None

    def test_get_node_returns_found(self) -> None:
        node = WorkflowNode(id="n1")
        wf = Workflow(nodes=[node])
        assert wf.get_node("n1") is node

    def test_progress_pct_empty_nodes(self) -> None:
        wf = Workflow()
        assert wf.progress_pct == 100.0

    def test_progress_pct_partial(self) -> None:
        wf = Workflow(
            nodes=[
                WorkflowNode(id="n1", status=WorkflowStepStatus.COMPLETED),
                WorkflowNode(id="n2", status=WorkflowStepStatus.PENDING),
            ]
        )
        assert wf.progress_pct == 50.0

    def test_is_complete_false_when_not_all_terminal(self) -> None:
        wf = Workflow(
            nodes=[
                WorkflowNode(id="n1", status=WorkflowStepStatus.COMPLETED),
                WorkflowNode(id="n2", status=WorkflowStepStatus.RUNNING),
            ]
        )
        assert wf.is_complete is False


class TestWorkflowEngineCancellation:
    @pytest.mark.asyncio
    async def test_run_workflow_cancelled_during_loop(self) -> None:
        engine = WorkflowEngine()

        async def slow_step(args):
            await asyncio.sleep(0.3)
            return {}

        engine.register_step("slow", slow_step)
        wf = engine.create_workflow(
            "test", nodes=[{"id": "n1", "step_fn": "slow"}]
        )
        task = asyncio.create_task(engine.run_workflow(wf))
        await asyncio.sleep(0.05)
        engine.cancel_workflow(wf.id)
        res = await task
        assert res.status == WorkflowStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_run_workflow_no_ready_nodes_and_none_running(self) -> None:
        engine = WorkflowEngine()
        wf = engine.create_workflow("test", nodes=[])
        res = await engine.run_workflow(wf)
        assert res.status == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_run_workflow_ready_but_running_nodes_waits(self) -> None:
        engine = WorkflowEngine()

        async def fast_step(args):
            return {"ok": True}

        async def blocker_step(args):
            await asyncio.sleep(0.2)
            return {"ok": True}

        engine.register_step("fast", fast_step)
        engine.register_step("blocker", blocker_step)
        wf = engine.create_workflow(
            "test",
            nodes=[
                {"id": "n1", "step_fn": "blocker"},
                {"id": "n2", "step_fn": "fast", "deps": ["n1"]},
            ],
            edges=[{"source": "n1", "target": "n2"}],
        )
        # Manually set n2 as RUNNING to simulate race
        wf.get_node("n2").status = WorkflowStepStatus.RUNNING
        task = asyncio.create_task(engine.run_workflow(wf))
        await asyncio.sleep(0.05)
        # n2 is still RUNNING, no ready nodes besides it
        engine.cancel_workflow(wf.id)
        res = await task
        assert res.status == WorkflowStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_run_node_generic_exception(self) -> None:
        engine = WorkflowEngine()

        async def failing_step(args):
            raise RuntimeError("Something went wrong")

        engine.register_step("failing", failing_step)
        wf = engine.create_workflow(
            "test", nodes=[{"id": "n1", "step_fn": "failing"}]
        )
        res = await engine.run_workflow(wf)
        node = res.get_node("n1")
        assert node.status == WorkflowStepStatus.FAILED
        assert "Something went wrong" in node.result["error"]

    def test_cancel_workflow_not_found(self) -> None:
        engine = WorkflowEngine()
        assert engine.cancel_workflow("nonexistent") is False

    def test_cancel_workflow_already_completed(self) -> None:
        engine = WorkflowEngine()
        wf = engine.create_workflow("test", nodes=[])
        wf.status = WorkflowStatus.COMPLETED
        for n in wf.nodes:
            n.status = WorkflowStepStatus.COMPLETED
        result = engine.cancel_workflow(wf.id)
        assert result is True
        assert wf.status == WorkflowStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_run_workflow_stalled_no_ready_no_running(self) -> None:
        """Scenario where no nodes are ready and none are running -> break."""
        engine = WorkflowEngine()

        async def step(args):
            return {}

        engine.register_step("step", step)
        wf = engine.create_workflow(
            "test",
            nodes=[
                {"id": "a", "step_fn": "step"},
                {"id": "b", "step_fn": "step"},
            ],
            edges=[
                {"source": "a", "target": "b", "condition": "always"}
            ],
        )
        # Mark 'a' as FAILED so 'b' can never become ready
        wf.get_node("a").status = WorkflowStepStatus.FAILED
        res = await engine.run_workflow(wf)
        # b should remain PENDING, workflow fails because not all completed
        assert res.status == WorkflowStatus.FAILED
        assert res.get_node("b").status == WorkflowStepStatus.PENDING

    def test_stats_with_running_and_completed(self) -> None:
        engine = WorkflowEngine()
        wf = engine.create_workflow("running_wf", nodes=[])
        wf.status = WorkflowStatus.RUNNING
        wf2 = engine.create_workflow("completed_wf", nodes=[])
        wf2.status = WorkflowStatus.COMPLETED
        engine.register_step("test", lambda _: None)
        stats = engine.stats()
        assert stats["total"] == 2
        assert stats["running"] == 1
        assert stats["completed"] == 1
        assert "test" in stats["registered_steps"]

    def test_workflow_node_is_terminal(self) -> None:
        for status in (
            WorkflowStepStatus.COMPLETED,
            WorkflowStepStatus.FAILED,
            WorkflowStepStatus.SKIPPED,
        ):
            node = WorkflowNode(id="x", status=status)
            assert node.is_terminal is True
        node = WorkflowNode(id="x", status=WorkflowStepStatus.PENDING)
        assert node.is_terminal is False

    def test_create_workflow_with_context(self) -> None:
        engine = WorkflowEngine()
        wf = engine.create_workflow(
            "test", context={"key": "value"}
        )
        assert wf.context == {"key": "value"}