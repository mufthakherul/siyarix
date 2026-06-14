# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for core/__init__.py — AgentCore (v2 goal decomposition & execution)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.core import AgentCore, AgentGoal, AgentResult, AgentMode, AgentStatus
from siyarix.planner import ExecutionPlan, PlanStep, PlanStatus, StepStatus
from siyarix.validators import RecoveryAction, RecoveryPlan


@pytest.fixture
def agent():
    return AgentCore(mode=AgentMode.REGISTRY)


@pytest.fixture
def goal():
    return AgentGoal(description="Scan target with nmap", target="10.0.0.1", priority=3)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInit:
    def test_init_defaults(self):
        agent = AgentCore()
        assert agent.mode == AgentMode.REGISTRY
        assert agent.status == AgentStatus.IDLE
        assert agent.registry is not None
        assert agent.planner is not None
        assert agent.executor is not None
        assert agent.validator is not None

    def test_init_registry_mode(self):
        agent = AgentCore(mode=AgentMode.REGISTRY)
        assert agent.mode == AgentMode.REGISTRY

    def test_init_autonomous_mode(self):
        agent = AgentCore(mode=AgentMode.AUTONOMOUS)
        assert agent.mode == AgentMode.AUTONOMOUS

    def test_init_hybrid_mode(self):
        agent = AgentCore(mode=AgentMode.HYBRID)
        assert agent.mode == AgentMode.HYBRID

    def test_init_interactive_mode(self):
        agent = AgentCore(mode=AgentMode.INTERACTIVE)
        assert agent.mode == AgentMode.INTERACTIVE

    def test_properties_expose_internals(self):
        agent = AgentCore()
        assert agent.memory is not None
        assert agent.providers is not None
        assert agent.context is not None


# ---------------------------------------------------------------------------
# AgentGoal
# ---------------------------------------------------------------------------


class TestAgentGoal:
    def test_goal_defaults(self):
        goal = AgentGoal()
        assert goal.description == ""
        assert goal.target == ""
        assert goal.constraints == {}
        assert goal.priority == 5
        assert goal.timeout == 600.0

    def test_goal_custom(self):
        goal = AgentGoal(description="hack the planet", target="10.0.0.1", priority=1, timeout=30.0)
        assert goal.description == "hack the planet"
        assert goal.priority == 1


# ---------------------------------------------------------------------------
# AgentResult
# ---------------------------------------------------------------------------


class TestAgentResult:
    def test_result_defaults(self):
        result = AgentResult()
        assert result.goal == ""
        assert result.success is False
        assert result.summary == ""
        assert result.plan is None
        assert result.duration_ms == 0.0
        assert result.findings == []
        assert result.metadata == {}

    def test_result_fields(self):
        plan = ExecutionPlan(goal="test")
        result = AgentResult(
            goal="scan target",
            success=True,
            summary="All done",
            plan=plan,
            duration_ms=123.4,
            findings=[{"tool": "nmap", "description": "port scan", "output_preview": "..."}],
        )
        assert result.goal == "scan target"
        assert result.success is True
        assert result.plan is plan
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# AgentStatus
# ---------------------------------------------------------------------------


class TestAgentStatus:
    def test_status_values(self):
        assert AgentStatus.IDLE == "idle"
        assert AgentStatus.PLANNING == "planning"
        assert AgentStatus.EXECUTING == "executing"
        assert AgentStatus.VALIDATING == "validating"
        assert AgentStatus.RECOVERING == "recovering"
        assert AgentStatus.REFLECTING == "reflecting"
        assert AgentStatus.COMPLETED == "completed"
        assert AgentStatus.FAILED == "failed"

    def test_status_transitions_on_success(self, agent):
        assert agent.status == AgentStatus.IDLE


# ---------------------------------------------------------------------------
# initialize
# ---------------------------------------------------------------------------


class TestInitialize:
    @pytest.mark.asyncio
    async def test_initialize_sets_up_registry(self, agent):
        with (
            patch.object(agent._registry, "discover_from_path") as mock_discover,
            patch.object(agent._event_bus, "emit", new_callable=AsyncMock),
        ):
            await agent.initialize()
            mock_discover.assert_called_once()


# ---------------------------------------------------------------------------
# execute_goal
# ---------------------------------------------------------------------------


class TestExecuteGoal:
    @pytest.mark.asyncio
    async def test_execute_goal_success(self, agent, goal):
        step = PlanStep(
            tool="nmap",
            args={"target": "10.0.0.1"},
            description="Port scan",
            status=StepStatus.COMPLETED,
            result={"output": "22/tcp open ssh"},
        )
        plan = ExecutionPlan(
            goal="Scan target with nmap", steps=[step], status=PlanStatus.COMPLETED
        )

        agent._planner.decompose_goal = MagicMock(return_value=plan)
        agent._validator.validate_plan = AsyncMock(return_value=[])
        agent._executor.execute_plan = AsyncMock(return_value=plan)

        result = await agent.execute_goal(goal)

        assert result.success is True
        assert result.goal == "Scan target with nmap"
        assert result.plan is plan
        assert result.duration_ms >= 0
        assert agent.status == AgentStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_goal_failure(self, agent, goal):
        step = PlanStep(tool="nmap", args={}, description="Port scan")
        plan = ExecutionPlan(goal="Scan target with nmap", steps=[step], status=PlanStatus.ACTIVE)

        agent._planner.decompose_goal = MagicMock(return_value=plan)
        agent._validator.validate_plan = AsyncMock(return_value=[])
        agent._executor.execute_plan = AsyncMock(return_value=plan)

        with patch.object(agent._executor, "execute_plan", new_callable=AsyncMock) as mock_exec:
            failed_step = PlanStep(
                tool="nmap",
                args={},
                description="Port scan",
                status=StepStatus.FAILED,
                result={"error": "connection refused"},
            )
            failed_plan = ExecutionPlan(
                goal="Scan target with nmap", steps=[failed_step], status=PlanStatus.FAILED
            )
            mock_exec.return_value = failed_plan
            agent._validator.plan_recovery = AsyncMock(
                return_value=RecoveryPlan(original_step=failed_step, action=RecoveryAction.SKIP)
            )

            result = await agent.execute_goal(goal)

            assert result.success is False
            assert agent.status == AgentStatus.FAILED

    @pytest.mark.asyncio
    async def test_execute_goal_exception(self, agent, goal):
        agent._planner.decompose_goal = MagicMock(side_effect=RuntimeError("planner crashed"))

        result = await agent.execute_goal(goal)

        assert result.success is False
        assert "failed" in result.summary
        assert agent.status == AgentStatus.FAILED

    @pytest.mark.asyncio
    async def test_execute_goal_records_history(self, agent, goal):
        step = PlanStep(tool="nmap", args={}, description="Scan")
        plan = ExecutionPlan(goal="Scan target with nmap", steps=[step], status=PlanStatus.ACTIVE)

        agent._planner.decompose_goal = MagicMock(return_value=plan)
        agent._validator.validate_plan = AsyncMock(return_value=[])
        agent._executor.execute_plan = AsyncMock(return_value=plan)

        result = await agent.execute_goal(goal)

        assert len(agent._history) == 1
        assert agent._history[0] is result

    @pytest.mark.asyncio
    async def test_execute_goal_sets_planning_status(self, agent, goal):
        status_during = []

        original_validate = agent._validator.validate_plan

        async def track_validate(steps):
            status_during.append(agent.status)
            return await original_validate(steps)

        step = PlanStep(tool="nmap", args={}, description="Scan")
        plan = ExecutionPlan(goal="Scan target with nmap", steps=[step], status=PlanStatus.ACTIVE)

        agent._planner.decompose_goal = MagicMock(return_value=plan)
        agent._validator.validate_plan = track_validate
        agent._executor.execute_plan = AsyncMock(return_value=plan)

        await agent.execute_goal(goal)

        assert AgentStatus.PLANNING in status_during

    @pytest.mark.asyncio
    async def test_execute_goal_finds_completed_steps(self, agent, goal):
        step = PlanStep(
            tool="nmap",
            args={},
            description="Port scan",
            status=StepStatus.COMPLETED,
            result={"output": "22/tcp open ssh"},
        )
        plan = ExecutionPlan(goal="Scan target with nmap", steps=[step], status=PlanStatus.ACTIVE)

        agent._planner.decompose_goal = MagicMock(return_value=plan)
        agent._validator.validate_plan = AsyncMock(return_value=[])
        agent._executor.execute_plan = AsyncMock(return_value=plan)

        result = await agent.execute_goal(goal)

        assert len(result.findings) == 1
        assert result.findings[0]["tool"] == "nmap"
        assert "22/tcp open ssh" in result.findings[0]["output_preview"]

    @pytest.mark.asyncio
    async def test_execute_goal_empty_plan(self, agent, goal):
        plan = ExecutionPlan(goal="Scan target with nmap", steps=[], status=PlanStatus.COMPLETED)

        agent._planner.decompose_goal = MagicMock(return_value=plan)
        agent._validator.validate_plan = AsyncMock(return_value=[])
        agent._executor.execute_plan = AsyncMock(return_value=plan)

        result = await agent.execute_goal(goal)

        assert result.success is True
        assert "0 steps" in result.summary

    @pytest.mark.asyncio
    async def test_execute_goal_recovery_retries(self, goal):
        autonomous_agent = AgentCore(mode=AgentMode.AUTONOMOUS)
        failed_step = PlanStep(
            tool="nmap",
            args={"target": "10.0.0.1"},
            description="Port scan",
            status=StepStatus.FAILED,
            result={"error": "filtered"},
        )
        failed_plan = ExecutionPlan(goal="Scan", steps=[failed_step], status=PlanStatus.ACTIVE)

        recovered_step = PlanStep(
            tool="nmap",
            args={"target": "10.0.0.1", "flags": "-Pn"},
            description="Port scan",
            status=StepStatus.COMPLETED,
            result={"output": "22/tcp open ssh"},
        )
        recovered_plan = ExecutionPlan(
            goal="Scan", steps=[recovered_step], status=PlanStatus.COMPLETED
        )

        autonomous_agent._planner.decompose_goal = MagicMock(return_value=failed_plan)
        autonomous_agent._planner.llm_decompose_goal = AsyncMock(return_value=failed_plan)
        autonomous_agent._validator.validate_plan = AsyncMock(return_value=[])
        autonomous_agent._executor.execute_plan = AsyncMock(
            side_effect=[failed_plan, recovered_plan]
        )
        autonomous_agent._validator.plan_recovery = AsyncMock(
            return_value=RecoveryPlan(
                original_step=failed_step, action=RecoveryAction.RETRY, modified_step=recovered_step
            )
        )

        result = await autonomous_agent.execute_goal(goal)

        assert result.success is True
        assert autonomous_agent._executor.execute_plan.call_count == 2


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_returns_dict(self, agent):
        stats = agent.stats()
        assert "mode" in stats
        assert "status" in stats
        assert "registry" in stats
        assert "history" in stats

    def test_stats_initial(self, agent):
        stats = agent.stats()
        assert stats["mode"] == "registry"
        assert stats["status"] == "idle"
        assert stats["history"] == 0
