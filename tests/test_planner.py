from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the new Planner module."""


import pytest

from siyarix.planner import (
    ExecutionPlan,
    PlanStep,
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



"""Extra tests for Planner router targeting uncovered lines."""


import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.planner import (
    ExecutionPlan,
    PlanStatus,
    PlanStep,
    Planner,
    StepStatus,
)
from siyarix.planner_autonomous import AutonomousPlanner


# ── Planner router tests ─────────────────────────────────────────────

class TestPlannerPlanMode:
    @pytest.fixture
    def planner(self):
        return Planner()

    @pytest.mark.asyncio
    async def test_plan_registry_mode(self, planner):
        plan = await planner.plan(
            "scan target", mode="registry", available_tools=["nmap"]
        )
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_offline_mode(self, planner):
        plan = await planner.plan(
            "scan target", mode="offline", available_tools=["nmap"]
        )
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_autonomous_mode(self, planner):
        llm_call = AsyncMock(
            return_value={
                "needs_tools": True,
                "reasoning": "test",
                "steps": [
                    {
                        "tool": "echo",
                        "command": "echo test",
                        "description": "test step",
                    }
                ],
            }
        )
        plan = await planner.plan(
            "test",
            mode="autonomous",
            llm_call=llm_call,
            tool_schemas=[{"name": "echo", "description": "echo cmd"}],
        )
        assert isinstance(plan, ExecutionPlan)

    @pytest.mark.asyncio
    async def test_plan_autonomous_no_llm_call(self, planner):
        with pytest.raises(RuntimeError, match="requires an llm_call"):
            await planner.plan("test", mode="autonomous")

    @pytest.mark.asyncio
    async def test_plan_integrated_registry_provider(self, planner):
        plan = await planner.plan(
            "scan target",
            mode="integrated",
            provider="registry",
            available_tools=["nmap"],
        )
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_integrated_fallback_to_registry(self, planner):
        failing_llm = AsyncMock(side_effect=RuntimeError("LLM failed"))
        planner._autonomous.plan = failing_llm
        plan = await planner.plan(
            "scan target",
            mode="integrated",
            llm_call=AsyncMock(),
            available_tools=["nmap"],
        )
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_integrated_empty_steps_fallback(self, planner):
        """Autonomous returns empty steps, falls back to registry."""
        empty_llm = AsyncMock(
            return_value={
                "needs_tools": False,
                "reasoning": "no tools needed",
            }
        )
        plan = await planner.plan(
            "scan target",
            mode="integrated",
            llm_call=empty_llm,
            available_tools=["nmap"],
        )
        # Should have registry steps
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) > 0


class TestPlannerIntegration:
    @pytest.fixture
    def planner(self):
        return Planner()

    def test_resolve_alternatives(self, planner):
        alts = planner.resolve_alternatives("recon_full", {"nmap"})
        assert isinstance(alts, list)

    def test_build_index(self, planner):
        planner.build_index(["nmap", "curl"])
        stats = planner.stats()
        assert "registry" in stats

    def test_decompose_goal(self, planner):
        plan = planner.decompose_goal("scan network", ["nmap"])
        assert isinstance(plan, ExecutionPlan)

    @pytest.mark.asyncio
    async def test_llm_decompose_goal(self, planner):
        llm_call = AsyncMock(
            return_value={
                "needs_tools": True,
                "reasoning": "test",
                "steps": [{"tool": "echo", "command": "echo hi", "description": "say hi"}],
            }
        )
        plan = await planner.llm_decompose_goal(
            "test", ["echo"], llm_call=llm_call
        )
        assert isinstance(plan, ExecutionPlan)

    @pytest.mark.asyncio
    async def test_llm_decompose_goal_no_steps(self, planner):
        llm_call = AsyncMock(
            return_value={
                "needs_tools": True,
                "reasoning": "test",
                "steps": [],
            }
        )
        plan = await planner.llm_decompose_goal(
            "test", ["echo"], llm_call=llm_call
        )
        assert isinstance(plan, ExecutionPlan)

    def test_get_plan_from_plans_dict(self, planner):
        plan = planner.create_plan("myplan")
        got = planner.get_plan(plan.id)
        assert got is plan

    def test_get_plan_from_registry(self, planner):
        plan = planner._registry.create_plan("registry_plan")
        got = planner.get_plan(plan.id)
        assert got is plan

    def test_get_plan_from_autonomous(self, planner):
        plan = planner._autonomous.create_plan("auto_plan")
        got = planner.get_plan(plan.id)
        assert got is plan

    def test_get_plan_not_found(self, planner):
        assert planner.get_plan("nonexistent") is None

    def test_list_plans_with_status_filter(self, planner):
        p1 = planner.create_plan("active_plan")
        p1.status = PlanStatus.ACTIVE
        p2 = planner.create_plan("completed_plan")
        p2.status = PlanStatus.COMPLETED
        active = planner.list_plans(status=PlanStatus.ACTIVE)
        assert len(active) == 1
        assert active[0].goal == "active_plan"

    def test_list_plans_deduplicates(self, planner):
        p1 = planner.create_plan("shared_goal")
        # Create same ID in autonomous
        planner._autonomous._plans[p1.id] = p1
        plans = planner.list_plans()
        ids = [p.id for p in plans]
        assert ids.count(p1.id) == 1

    def test_stats_aggregates(self, planner):
        planner.create_plan("p1")
        planner._autonomous.create_plan("ap1")
        stats = planner.stats()
        assert stats["total_plans"] >= 2
        assert "registry" in stats
        assert "autonomous" in stats
        assert stats["router"]["mode"] == "multi"

    def test_adapt_plan(self, planner):
        plan = planner.create_plan(
            "test",
            steps=[{"tool": "nmap", "args": {"target": "x"}}],
        )
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        step.result = {"error": "filtered"}
        adapted = planner.adapt_plan(plan, step, "filtered")
        assert isinstance(adapted, ExecutionPlan)

    def test_properties_autonomous_and_registry(self, planner):
        assert planner.autonomous_planner is planner._autonomous
        assert planner.registry_planner is planner._registry


# ── AutonomousPlanner extra tests ────────────────────────────────────

class TestAutonomousPlannerIntegration:
    @pytest.fixture
    def ap(self):
        return AutonomousPlanner()

    def test_reset_session(self, ap):
        ap.mark_session_initialised()
        assert ap.session_initialised is True
        ap.reset_session()
        assert ap.session_initialised is False

    def test_build_platform_context_contains_shell(self, ap):
        ctx = ap._build_platform_context()
        assert "Shell:" in ctx

    def test_build_first_prompt_with_system_prompt(self, ap):
        prompt = ap._build_first_prompt(
            system_prompt="You are a helper.",
            user_goal="scan",
            platform_info="Linux system",
            tool_schemas=[{"name": "nmap", "description": "Network mapper"}],
        )
        assert "You are a helper." in prompt
        assert "nmap" in prompt

    def test_build_first_prompt_with_available_tools(self, ap):
        prompt = ap._build_first_prompt(
            system_prompt=None,
            user_goal="scan",
            platform_info="Linux",
            tool_schemas=None,
            available_tools=["nmap", "curl"],
        )
        assert "nmap" in prompt or "curl" in prompt

    def test_build_first_prompt_without_tools(self, ap):
        prompt = ap._build_first_prompt(
            system_prompt=None,
            user_goal="hello",
            platform_info="Linux",
            tool_schemas=None,
            available_tools=None,
        )
        assert "hello" in prompt

    def test_build_first_prompt_tool_schema_with_tags_cat(self, ap):
        prompt = ap._build_first_prompt(
            system_prompt="Custom",
            user_goal="scan",
            platform_info="Linux",
            tool_schemas=[{
                "name": "nmap",
                "description": "Network mapper",
                "tags": ["port-scan", "network"],
                "category": "recon",
            }],
        )
        assert "[port-scan, network]" in prompt
        assert "(recon)" in prompt

    def test_build_subsequent_prompt_with_history(self, ap):
        prompt = ap._build_subsequent_prompt(
            system_prompt=None,
            user_goal="continue",
            platform_info="Linux",
            history=[
                {"role": "user", "content": "previous command"},
            ],
        )
        assert "continue" in prompt
        assert "previous command" in prompt

    def test_build_subsequent_prompt_with_system_prompt(self, ap):
        prompt = ap._build_subsequent_prompt(
            system_prompt="Continue as assistant.",
            user_goal="next step",
            platform_info="Linux",
            history=[],
        )
        assert "Continue as assistant." in prompt

    def test_build_subsequent_prompt_empty_history(self, ap):
        prompt = ap._build_subsequent_prompt(
            system_prompt="Base",
            user_goal="goal",
            platform_info="Linux",
            history=None,
        )
        assert "goal" in prompt

    @pytest.mark.asyncio
    async def test_plan_empty_llm_response(self, ap):
        llm_call = AsyncMock(return_value={})
        plan = await ap.plan("test", llm_call=llm_call)
        assert isinstance(plan, ExecutionPlan)
        assert plan.context.get("llm_planned") is True

    @pytest.mark.asyncio
    async def test_plan_no_needs_tools(self, ap):
        llm_call = AsyncMock(
            return_value={
                "needs_tools": False,
                "reasoning": "Just a chat response",
            }
        )
        plan = await ap.plan("hello", llm_call=llm_call)
        assert isinstance(plan, ExecutionPlan)

    @pytest.mark.asyncio
    async def test_plan_empty_steps_after_parsing(self, ap):
        llm_call = AsyncMock(
            return_value={
                "needs_tools": True,
                "reasoning": "test",
                "steps": [],
            }
        )
        plan = await ap.plan("test", llm_call=llm_call)
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) == 0

    @pytest.mark.asyncio
    async def test_plan_with_is_first_call_override(self, ap):
        """is_first_call=False should skip full prompt even if session not init."""
        llm_call = AsyncMock(
            return_value={
                "needs_tools": True,
                "reasoning": "test",
                "steps": [{"tool": "echo", "command": "echo hi", "description": "say hi"}],
            }
        )
        plan = await ap.plan(
            "test", llm_call=llm_call, is_first_call=False
        )
        assert isinstance(plan, ExecutionPlan)
        # Session should remain uninitialised since we passed is_first_call=False
        assert ap.session_initialised is False

    @pytest.mark.asyncio
    async def test_plan_llm_call_exception(self, ap):
        llm_call = AsyncMock(side_effect=ValueError("LLM error"))
        with pytest.raises(RuntimeError, match="LLM planning call failed"):
            await ap.plan("test", llm_call=llm_call)

    @pytest.mark.asyncio
    async def test_plan_with_tool_calls_response(self, ap):
        """When raw response has tool_calls, parse via function arguments."""
        llm_call = AsyncMock(
            return_value={
                "tool_calls": [
                    MagicMock(
                        function=MagicMock(
                            arguments='{"needs_tools": true, "reasoning": "t", "steps": [{"tool": "echo", "command": "echo hi", "description": "say hi"}]}'
                        )
                    )
                ]
            }
        )
        plan = await ap.plan("test", llm_call=llm_call)
        assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_with_tool_calls_dict_args(self, ap):
        """tool_calls with dict arguments (not str)."""
        mock_tc = MagicMock()
        mock_tc.function.arguments = {
            "needs_tools": True,
            "reasoning": "test",
            "steps": [{"tool": "echo", "command": "echo hi", "description": "say hi"}],
        }
        llm_call = AsyncMock(
            return_value={"tool_calls": [mock_tc]}
        )
        plan = await ap.plan("test", llm_call=llm_call)
        assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_non_dict_data(self, ap):
        """When parsed data is not a dict, create plan with string response."""
        llm_call = AsyncMock(
            return_value={
                "content": "Plain text response",
            }
        )
        plan = await ap.plan("test", llm_call=llm_call)
        assert isinstance(plan, ExecutionPlan)
        assert plan.context.get("llm_planned") is True

    @pytest.mark.asyncio
    async def test_plan_steps_with_non_dict_entries(self, ap):
        """Steps list containing non-dict items."""
        content = json.dumps({
            "needs_tools": True,
            "reasoning": "test",
            "steps": [
                "raw_step_string",
                {"tool": "echo", "command": "echo hi", "description": "say hi"},
            ],
        })
        llm_call = AsyncMock(return_value={"content": content})
        plan = await ap.plan("test", llm_call=llm_call)
        assert len(plan.steps) == 2
        assert "raw_step_string" in plan.steps[0].description

    @pytest.mark.asyncio
    async def test_plan_steps_with_none_entries(self, ap):
        """Steps list containing None."""
        content = json.dumps({
            "needs_tools": True,
            "reasoning": "test",
            "steps": [None],
        })
        llm_call = AsyncMock(return_value={"content": content})
        plan = await ap.plan("test", llm_call=llm_call)
        assert len(plan.steps) == 1
        assert "LLM step 1" in plan.steps[0].description

    def test_parse_llm_response_tool_calls_invalid_json(self, ap):
        raw = {
            "tool_calls": [
                MagicMock(
                    function=MagicMock(
                        arguments="not valid json"
                    )
                )
            ]
        }
        result = ap._parse_llm_response(raw)
        assert result is None

    def test_parse_llm_response_json_from_content(self, ap):
        raw = {
            "content": '{"needs_tools": true, "reasoning": "test", "steps": []}'
        }
        result = ap._parse_llm_response(raw)
        assert isinstance(result, dict)
        assert result["needs_tools"] is True

    def test_parse_llm_response_markdown_json(self, ap):
        raw = {
            "content": "```json\n{\"needs_tools\": false, \"reasoning\": \"ok\"}\n```"
        }
        result = ap._parse_llm_response(raw)
        assert isinstance(result, dict)
        assert result["needs_tools"] is False

    def test_parse_llm_response_invalid_json_content(self, ap):
        raw = {"content": "not json at all"}
        result = ap._parse_llm_response(raw)
        assert result is None

    def test_parse_llm_response_not_dict(self, ap):
        result = ap._parse_llm_response("just a string")
        assert result is None

    def test_list_plans_with_status_filter(self, ap):
        p1 = ap.create_plan("active_plan")
        p2 = ap.create_plan("completed_plan", steps=[{"tool": "echo", "description": "test"}])
        ap.get_plan(p2.id).status = PlanStatus.COMPLETED
        filtered = ap.list_plans(status=PlanStatus.ACTIVE)
        assert len(filtered) == 1
        assert filtered[0].goal == "active_plan"

    def test_list_plans_all(self, ap):
        ap.create_plan("p1")
        ap.create_plan("p2")
        plans = ap.list_plans()
        assert len(plans) == 2

    def test_stats_values(self, ap):
        ap.create_plan("active_plan")
        ap.create_plan("completed_plan")
        s = ap.stats()
        assert s["total_plans"] == 2
        # create_plan always sets status to ACTIVE
        assert s["active"] == 2
        assert s["completed"] == 0
        assert s["session_initialised"] is False

    def test_steps_with_dependencies(self, ap):
        plan = ap.create_plan(
            "test",
            steps=[
                {
                    "id": "step_000",
                    "description": "First step",
                    "tool": "nmap",
                    "args": {"target": "x"},
                    "command": "nmap -sV x",
                    "dependencies": [],
                    "timeout": 120.0,
                },
            ],
        )
        assert len(plan.steps) == 1
        assert plan.steps[0].id == "step_000"
        assert plan.steps[0].timeout == 120.0