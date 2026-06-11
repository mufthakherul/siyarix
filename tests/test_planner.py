# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the new Planner module."""

from __future__ import annotations

import pytest

from siyarix.planner import (
    ExecutionPlan,
    PlanStep,
    PlanType,
    PlanStatus,
    StepStatus,
    Planner,
)


class TestPlanStep:
    def test_creation(self):
        step = PlanStep(tool="nmap", args={"target": "192.168.1.1"})
        assert step.tool == "nmap"
        assert step.status == StepStatus.PENDING
        assert step.is_ready
        assert step.can_retry

    def test_terminal_states(self):
        step = PlanStep(tool="nmap", status=StepStatus.COMPLETED)
        assert step.is_terminal
        assert not step.is_ready

    def test_retry_limit(self):
        step = PlanStep(tool="nmap", retry_count=3, max_retries=3)
        assert not step.can_retry


class TestExecutionPlan:
    def test_creation(self):
        plan = ExecutionPlan(goal="Scan target")
        assert plan.goal == "Scan target"
        assert plan.status == PlanStatus.DRAFT
        assert plan.progress_pct == 100.0

    def test_steps_tracking(self):
        plan = ExecutionPlan(
            goal="Test",
            steps=[
                PlanStep(tool="nmap", status=StepStatus.COMPLETED),
                PlanStep(tool="nuclei", status=StepStatus.FAILED),
                PlanStep(tool="gobuster"),
            ],
        )
        assert len(plan.completed_steps) == 1
        assert len(plan.failed_steps) == 1
        assert len(plan.pending_steps) == 1
        assert not plan.is_complete
        assert plan.has_failures

    def test_to_dict(self):
        plan = ExecutionPlan(goal="Test", steps=[PlanStep(tool="nmap")])
        d = plan.to_dict()
        assert d["goal"] == "Test"
        assert len(d["steps"]) == 1


class TestPlanner:
    def test_create_plan(self):
        p = Planner()
        plan = p.create_plan(
            "Scan target",
            steps=[
                {"description": "Port scan", "tool": "nmap", "args": {"target": "10.0.0.1"}},
            ],
        )
        assert plan.goal == "Scan target"
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "nmap"

    def test_create_from_template(self):
        p = Planner()
        plan = p.create_from_template("recon_full", "192.168.1.1")
        assert "192.168.1.1" in plan.goal
        assert len(plan.steps) == 6

    def test_create_from_unknown_template(self):
        p = Planner()
        with pytest.raises(ValueError, match="Unknown template"):
            p.create_from_template("nonexistent", "target")

    def test_decompose_goal_recon(self):
        p = Planner()
        plan = p.decompose_goal("recon the target")
        assert len(plan.steps) > 0

    def test_decompose_goal_web(self):
        p = Planner()
        plan = p.decompose_goal("scan web server")
        assert len(plan.steps) > 0

    def test_decompose_goal_brute(self):
        p = Planner()
        plan = p.decompose_goal("brute force passwords")
        assert len(plan.steps) > 0

    def test_adapt_plan_nmap_filtered(self):
        p = Planner()
        plan = p.create_plan("test", steps=[{"tool": "nmap", "args": {"target": "x"}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        step.result = {"error": "filtered"}
        p.adapt_plan(plan, step, "filtered")
        assert "-Pn" in step.args.get("flags", "")

    def test_adapt_plan_max_retries(self):
        p = Planner()
        plan = p.create_plan("test", steps=[{"tool": "nmap", "args": {}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        step.retry_count = 3
        step.max_retries = 3
        step.result = {"error": "unknown"}
        p.adapt_plan(plan, step, "unknown")
        assert step.status == StepStatus.FAILED

    def test_list_plans(self):
        p = Planner()
        p.create_plan("Plan 1")
        p.create_plan("Plan 2")
        plans = p.list_plans()
        assert len(plans) == 2

    def test_stats(self):
        p = Planner()
        stats = p.stats()
        assert "total_plans" in stats
        assert "templates" in stats
