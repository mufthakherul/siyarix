from __future__ import annotations

import pytest

from siyarix.core.pipeline import CommandPipeline, PipelineStep
from siyarix.core.swarm import SwarmRouter


def test_pipeline_parse():
    pipeline = CommandPipeline()

    steps = pipeline.parse("scan 127.0.0.1")
    assert len(steps) == 1
    assert steps[0].instruction == "scan 127.0.0.1"

    steps = pipeline.parse("scan | grep open | report")
    assert len(steps) == 3
    assert steps[1].instruction == "grep open"

    steps = pipeline.parse("scan then report")
    assert len(steps) == 2

    steps = pipeline.parse("scan and then exploit")
    assert len(steps) == 2

    steps = pipeline.parse("scan followed by report")
    assert len(steps) == 2


@pytest.mark.asyncio
async def test_pipeline_execute():
    pipeline = CommandPipeline()
    steps = [
        PipelineStep(instruction="test 1", step_id="1"),
        PipelineStep(instruction="test 2", step_id="2"),
    ]

    async def mock_executor(step, ctx):
        if step.instruction == "test 1":
            return {"status": "completed", "findings": ["A"], "output": "Done 1"}
        elif step.instruction == "test 2":
            return {"status": "failed"}

    result = await pipeline.execute(steps, mock_executor)
    assert result.steps_completed == 1
    assert result.steps_failed == 1
    assert result.success is False
    assert result.all_findings == ["A"]


@pytest.mark.asyncio
async def test_pipeline_execute_exception():
    pipeline = CommandPipeline()
    steps = [PipelineStep(instruction="fail", step_id="1")]

    async def mock_executor(step, ctx):
        raise ValueError("Boom")

    result = await pipeline.execute(steps, mock_executor)
    assert result.steps_failed == 1
    assert result.success is False


@pytest.mark.asyncio
async def test_swarm_router_disabled_by_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SIYARIX_EXPERIMENTAL_SWARM", raising=False)
    router = SwarmRouter()
    res = await router.run_campaign("127.0.0.1")
    assert res["status"] == "not_implemented"
    assert res["recon_result"] is None


@pytest.mark.asyncio
async def test_swarm_router_experimental_stub(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SIYARIX_EXPERIMENTAL_SWARM", "1")
    router = SwarmRouter()
    res = await router.run_campaign("127.0.0.1")
    assert res["status"] == "not_implemented"
    assert res["recon_result"] is not None
    assert res["recon_result"]["status"] == "not_implemented"
    assert res["recon_result"]["implemented"] is False
    assert res["exploit_result"]["findings"] == []
    assert res["report_result"]["agent"] == "ReportAgent"


# ═══════════════════════════════════════════════════════════════════
# credential_store.py (71% - selective key lines)
# ═══════════════════════════════════════════════════════════════════
