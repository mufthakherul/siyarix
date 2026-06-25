"""Tests for siyarix.models - Data models for the planning system."""

from __future__ import annotations


from siyarix.models import (
    ExecutionPlan,
    ExecutionStep,
    PlanStatus,
    PlanStep,
    PlanType,
    StepResult,
    StepStatus,
    StepType,
)


class TestPlanStatus:
    def test_values(self):
        assert PlanStatus.DRAFT == "draft"
        assert PlanStatus.ACTIVE == "active"
        assert PlanStatus.PAUSED == "paused"
        assert PlanStatus.COMPLETED == "completed"
        assert PlanStatus.FAILED == "failed"
        assert PlanStatus.CANCELLED == "cancelled"

    def test_members(self):
        assert len(PlanStatus) == 6


class TestStepStatus:
    def test_values(self):
        assert StepStatus.PENDING == "pending"
        assert StepStatus.READY == "ready"
        assert StepStatus.RUNNING == "running"
        assert StepStatus.COMPLETED == "completed"
        assert StepStatus.FAILED == "failed"
        assert StepStatus.SKIPPED == "skipped"
        assert StepStatus.RETRYING == "retrying"
        assert StepStatus.BLOCKED == "blocked"

    def test_members(self):
        assert len(StepStatus) == 8


class TestPlanType:
    def test_values(self):
        assert PlanType.SEQUENTIAL == "sequential"
        assert PlanType.PARALLEL == "parallel"
        assert PlanType.DAG == "dag"
        assert PlanType.REACT == "react"
        assert PlanType.ADAPTIVE == "adaptive"

    def test_members(self):
        assert len(PlanType) == 5


class TestStepType:
    def test_values(self):
        assert StepType.TOOL_RUN == "tool_run"
        assert StepType.SHELL_CMD == "shell_cmd"
        assert StepType.ANALYSIS == "analysis"
        assert StepType.REPORT == "report"
        assert StepType.NETWORK == "network"
        assert StepType.WEB == "web"

    def test_members(self):
        assert len(StepType) == 6


class TestExecutionStep:
    def test_defaults(self):
        step = ExecutionStep()
        assert isinstance(step.id, str)
        assert len(step.id) == 32
        assert step.step_type == StepType.TOOL_RUN
        assert step.tool == ""
        assert step.args == []
        assert step.target == ""
        assert step.depends_on == []
        assert step.command is None
        assert step.description == ""
        assert step.timeout == 300.0
        assert step.metadata == {}

    def test_custom_values(self):
        step = ExecutionStep(
            id="custom_id",
            step_type=StepType.SHELL_CMD,
            tool="nmap",
            args=["-sV"],
            target="10.0.0.1",
            depends_on=["step_0"],
            command="nmap -sV 10.0.0.1",
            description="Version scan",
            timeout=600.0,
            metadata={"risk": "low"},
        )
        assert step.id == "custom_id"
        assert step.step_type == StepType.SHELL_CMD
        assert step.tool == "nmap"
        assert step.args == ["-sV"]
        assert step.target == "10.0.0.1"
        assert step.depends_on == ["step_0"]
        assert step.command == "nmap -sV 10.0.0.1"
        assert step.description == "Version scan"
        assert step.timeout == 600.0
        assert step.metadata == {"risk": "low"}

    def test_to_plan_step(self):
        step = ExecutionStep(
            tool="nmap",
            description="Nmap scan",
            target="10.0.0.1",
            command="nmap -sV",
            depends_on=["prev"],
            timeout=500.0,
            metadata={"src": "test"},
        )
        plan_step = step.to_plan_step()
        assert isinstance(plan_step, PlanStep)
        assert plan_step.id == step.id
        assert plan_step.description == "Nmap scan"
        assert plan_step.tool == "nmap"
        assert plan_step.args == {"target": "10.0.0.1"}
        assert plan_step.command == "nmap -sV"
        assert plan_step.dependencies == ["prev"]
        assert plan_step.timeout == 500.0
        assert plan_step.metadata == {"src": "test"}

    def test_to_plan_step_no_target(self):
        step = ExecutionStep(tool="report", description="Generate report")
        plan_step = step.to_plan_step()
        assert plan_step.args == {}

    def test_unique_ids(self):
        step1 = ExecutionStep()
        step2 = ExecutionStep()
        assert step1.id != step2.id


class TestPlanStep:
    def test_defaults(self):
        step = PlanStep()
        assert isinstance(step.id, str)
        assert len(step.id) == 32
        assert step.description == ""
        assert step.tool == ""
        assert step.args == {}
        assert step.command is None
        assert step.status == StepStatus.PENDING
        assert step.result == {}
        assert step.dependencies == []
        assert step.retry_count == 0
        assert step.max_retries == 3
        assert step.timeout == 300.0
        assert step.duration_ms == 0.0
        assert step.metadata == {}

    def test_custom_values(self):
        step = PlanStep(
            id="step_1",
            description="Scan ports",
            tool="nmap",
            args={"target": "10.0.0.1"},
            command="nmap -p- 10.0.0.1",
            status=StepStatus.RUNNING,
            result={"output": "open ports"},
            dependencies=["step_0"],
            retry_count=1,
            max_retries=5,
            timeout=600.0,
            duration_ms=1500.0,
            metadata={"env": "prod"},
        )
        assert step.id == "step_1"
        assert step.description == "Scan ports"
        assert step.tool == "nmap"
        assert step.args == {"target": "10.0.0.1"}
        assert step.command == "nmap -p- 10.0.0.1"
        assert step.status == StepStatus.RUNNING
        assert step.result == {"output": "open ports"}
        assert step.dependencies == ["step_0"]
        assert step.retry_count == 1
        assert step.max_retries == 5
        assert step.timeout == 600.0
        assert step.duration_ms == 1500.0
        assert step.metadata == {"env": "prod"}

    def test_hash(self):
        step1 = PlanStep(id="same_id")
        step2 = PlanStep(id="same_id")
        assert hash(step1) == hash(step2)

    def test_eq(self):
        step1 = PlanStep(id="id1")
        step2 = PlanStep(id="id1")
        step3 = PlanStep(id="id2")
        assert step1 == step2
        assert step1 != step3

    def test_eq_not_implemented(self):
        step = PlanStep()
        assert (step == "not_a_step") is False

    def test_is_ready_pending(self):
        step = PlanStep(status=StepStatus.PENDING)
        assert step.is_ready is True

    def test_is_ready_not_pending(self):
        step = PlanStep(status=StepStatus.RUNNING)
        assert step.is_ready is False

    def test_can_retry_true(self):
        step = PlanStep(retry_count=0, max_retries=3)
        assert step.can_retry is True

    def test_can_retry_false_equal(self):
        step = PlanStep(retry_count=3, max_retries=3)
        assert step.can_retry is False

    def test_can_retry_false_exceeded(self):
        step = PlanStep(retry_count=5, max_retries=3)
        assert step.can_retry is False

    def test_is_terminal_completed(self):
        assert PlanStep(status=StepStatus.COMPLETED).is_terminal is True

    def test_is_terminal_failed(self):
        assert PlanStep(status=StepStatus.FAILED).is_terminal is True

    def test_is_terminal_skipped(self):
        assert PlanStep(status=StepStatus.SKIPPED).is_terminal is True

    def test_is_terminal_false(self):
        assert PlanStep(status=StepStatus.RUNNING).is_terminal is False

    def test_unique_ids(self):
        step1 = PlanStep()
        step2 = PlanStep()
        assert step1.id != step2.id


class TestStepResult:
    def test_defaults(self):
        r = StepResult()
        assert r.step_id == ""
        assert r.status == StepStatus.PENDING
        assert r.output == ""
        assert r.error == ""
        assert r.findings == []
        assert r.retry_count == 0
        assert r.exit_code is None
        assert r.duration_ms == 0.0

    def test_custom_values(self):
        r = StepResult(
            step_id="step_1",
            status=StepStatus.COMPLETED,
            output="scan complete",
            error="",
            findings=[{"port": 80}],
            retry_count=1,
            exit_code=0,
            duration_ms=500.0,
        )
        assert r.step_id == "step_1"
        assert r.status == StepStatus.COMPLETED
        assert r.output == "scan complete"
        assert r.findings == [{"port": 80}]
        assert r.retry_count == 1
        assert r.exit_code == 0
        assert r.duration_ms == 500.0


class TestExecutionPlan:
    def test_defaults(self):
        plan = ExecutionPlan()
        assert isinstance(plan.id, str)
        assert len(plan.id) == 32
        assert plan.goal == ""
        assert plan.plan_type == PlanType.SEQUENTIAL
        assert plan.status == PlanStatus.DRAFT
        assert plan.steps == []
        assert plan.context == {}
        assert isinstance(plan.created_at, float)
        assert plan.metadata == {}
        assert plan.raw_instruction == ""
        assert plan.source == ""
        assert plan.confidence == 1.0

    def test_custom_values(self):
        steps = [PlanStep(description="step1")]
        plan = ExecutionPlan(
            id="plan_1",
            goal="Scan network",
            plan_type=PlanType.PARALLEL,
            status=PlanStatus.ACTIVE,
            steps=steps,
            context={"target": "10.0.0.0/24"},
            metadata={"author": "admin"},
            raw_instruction="scan the network",
            source="cli",
            confidence=0.95,
        )
        assert plan.id == "plan_1"
        assert plan.goal == "Scan network"
        assert plan.plan_type == PlanType.PARALLEL
        assert plan.status == PlanStatus.ACTIVE
        assert len(plan.steps) == 1
        assert plan.context == {"target": "10.0.0.0/24"}
        assert plan.metadata == {"author": "admin"}
        assert plan.raw_instruction == "scan the network"
        assert plan.source == "cli"
        assert plan.confidence == 0.95

    def test_completed_steps(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.COMPLETED),
                PlanStep(status=StepStatus.FAILED),
                PlanStep(status=StepStatus.PENDING),
            ]
        )
        assert len(plan.completed_steps) == 1

    def test_failed_steps(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.COMPLETED),
                PlanStep(status=StepStatus.FAILED),
                PlanStep(status=StepStatus.FAILED),
            ]
        )
        assert len(plan.failed_steps) == 2

    def test_pending_steps(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.PENDING),
                PlanStep(status=StepStatus.READY),
                PlanStep(status=StepStatus.COMPLETED),
            ]
        )
        assert len(plan.pending_steps) == 2

    def test_is_complete_all_terminal(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.COMPLETED),
                PlanStep(status=StepStatus.FAILED),
            ]
        )
        assert plan.is_complete is True

    def test_is_complete_not_all_terminal(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.COMPLETED),
                PlanStep(status=StepStatus.RUNNING),
            ]
        )
        assert plan.is_complete is False

    def test_is_complete_empty_steps(self):
        plan = ExecutionPlan()
        assert plan.is_complete is True

    def test_has_failures_true(self):
        plan = ExecutionPlan(steps=[PlanStep(status=StepStatus.FAILED)])
        assert plan.has_failures is True

    def test_has_failures_false(self):
        plan = ExecutionPlan(steps=[PlanStep(status=StepStatus.COMPLETED)])
        assert plan.has_failures is False

    def test_has_failures_empty(self):
        plan = ExecutionPlan()
        assert plan.has_failures is False

    def test_progress_pct_full(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.COMPLETED),
                PlanStep(status=StepStatus.COMPLETED),
            ]
        )
        assert plan.progress_pct == 100.0

    def test_progress_pct_partial(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.COMPLETED),
                PlanStep(status=StepStatus.PENDING),
                PlanStep(status=StepStatus.SKIPPED),
                PlanStep(status=StepStatus.FAILED),
            ]
        )
        assert plan.progress_pct == 50.0

    def test_progress_pct_zero(self):
        plan = ExecutionPlan(
            steps=[
                PlanStep(status=StepStatus.PENDING),
                PlanStep(status=StepStatus.PENDING),
            ]
        )
        assert plan.progress_pct == 0.0

    def test_progress_pct_empty(self):
        plan = ExecutionPlan()
        assert plan.progress_pct == 100.0

    def test_get_step_found(self):
        step = PlanStep(id="find_me")
        plan = ExecutionPlan(steps=[step])
        assert plan.get_step("find_me") is step

    def test_get_step_not_found(self):
        plan = ExecutionPlan(steps=[PlanStep(id="other")])
        assert plan.get_step("missing") is None

    def test_get_ready_steps(self):
        step_a = PlanStep(id="a", status=StepStatus.PENDING)
        step_b = PlanStep(id="b", status=StepStatus.PENDING, dependencies=["a"])
        step_c = PlanStep(id="c", status=StepStatus.PENDING, dependencies=["a"])
        step_completed = PlanStep(id="a_complete", status=StepStatus.COMPLETED)
        plan = ExecutionPlan(steps=[step_completed, step_a, step_b, step_c])
        ready = plan.get_ready_steps()
        assert step_a in ready
        assert step_b not in ready
        assert step_c not in ready
        assert step_a.status == StepStatus.READY

    def test_get_ready_steps_all_deps_met(self):
        step_a = PlanStep(id="a", status=StepStatus.COMPLETED)
        step_b = PlanStep(id="b", status=StepStatus.PENDING, dependencies=["a"])
        plan = ExecutionPlan(steps=[step_a, step_b])
        ready = plan.get_ready_steps()
        assert step_b in ready
        assert step_b.status == StepStatus.READY

    def test_get_ready_steps_no_pending(self):
        plan = ExecutionPlan(steps=[PlanStep(status=StepStatus.COMPLETED)])
        assert plan.get_ready_steps() == []

    def test_get_ready_steps_already_ready(self):
        step = PlanStep(id="r", status=StepStatus.READY)
        plan = ExecutionPlan(steps=[step])
        ready = plan.get_ready_steps()
        assert step in ready

    def test_get_ready_steps_dep_not_found(self):
        step = PlanStep(id="s", status=StepStatus.PENDING, dependencies=["missing"])
        plan = ExecutionPlan(steps=[step])
        ready = plan.get_ready_steps()
        assert ready == []

    def test_get_ready_steps_dep_not_completed(self):
        step_a = PlanStep(id="a", status=StepStatus.PENDING)
        step_b = PlanStep(id="b", status=StepStatus.PENDING, dependencies=["a"])
        plan = ExecutionPlan(steps=[step_a, step_b])
        ready = plan.get_ready_steps()
        assert step_a in ready
        assert step_b not in ready

    def test_to_dict(self):
        step = PlanStep(id="s1", description="Scan", tool="nmap", status=StepStatus.COMPLETED)
        plan = ExecutionPlan(
            id="p1",
            goal="test goal",
            plan_type=PlanType.SEQUENTIAL,
            status=PlanStatus.ACTIVE,
            steps=[step],
        )
        d = plan.to_dict()
        assert d["id"] == "p1"
        assert d["goal"] == "test goal"
        assert d["type"] == "sequential"
        assert d["status"] == "active"
        assert d["progress"] == 100.0
        assert len(d["steps"]) == 1
        assert d["steps"][0]["id"] == "s1"
        assert d["steps"][0]["status"] == "completed"

    def test_to_dict_empty_steps(self):
        plan = ExecutionPlan()
        d = plan.to_dict()
        assert d["steps"] == []

    def test_unique_ids(self):
        plan1 = ExecutionPlan()
        plan2 = ExecutionPlan()
        assert plan1.id != plan2.id


class TestPublicAPI:
    def test_all_exports(self):
        from siyarix import models

        expected = [
            "PlanStatus",
            "StepStatus",
            "PlanType",
            "StepType",
            "ExecutionStep",
            "PlanStep",
            "StepResult",
            "ExecutionPlan",
        ]
        for name in expected:
            assert hasattr(models, name)
