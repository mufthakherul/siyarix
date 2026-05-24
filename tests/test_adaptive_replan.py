import asyncio

from phalanx.engine import ExecutionEngine
from phalanx.engine_types import StepResult, StepStatus
from phalanx.planner import ExecutionPlan, ExecutionStep, StepType


def test_planner_replan_fallback_for_zero_findings() -> None:
    engine = ExecutionEngine()
    step = ExecutionStep(
        id="scan_1",
        step_type=StepType.TOOL_RUN,
        tool="gobuster",
        target="example.com",
    )
    sr = StepResult(step_id="scan_1", status=StepStatus.SUCCESS, findings=[])
    plan = ExecutionPlan(steps=[step], raw_instruction="scan example.com")
    pending: list[ExecutionStep] = []

    asyncio.run(engine._replan_from_feedback(step, sr, plan, pending))

    assert pending
    assert any("adaptive" in s.id for s in pending)
    assert pending[0].depends_on == ["scan_1"]
