# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.planner import ExecutionPlan, PlanStep, Planner, StepStatus


def test_planner_adapt_plan_for_zero_findings() -> None:
    planner = Planner()
    step = PlanStep(id="scan_1", tool="gobuster", args={"target": "example.com"})
    plan = ExecutionPlan(
        steps=[step],
        raw_instruction="scan example.com",
    )
    step.status = StepStatus.COMPLETED
    step.result = {"output": ""}

    adapted = planner.adapt_plan(plan, step, "404")

    adapted_step = adapted.steps[0]
    assert adapted_step.retry_count > 0 or "extensions" in adapted_step.args
