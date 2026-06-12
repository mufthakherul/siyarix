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
