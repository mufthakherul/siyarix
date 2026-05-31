# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio

from siyarix.compat import ExecutionEngine
from siyarix.planner import StepResult, StepStatus
from siyarix.planner import ExecutionPlan, ExecutionStep, StepType


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
