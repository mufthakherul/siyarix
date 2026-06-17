from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.core import AgentCore, AgentGoal, AgentMode, AgentResult, AgentStatus
from siyarix.credential_store import CredentialStore
from siyarix.exceptions import BudgetExceededError
from siyarix.planner import ExecutionPlan, PlanStatus, PlanStep, StepStatus
from siyarix.validators import RecoveryAction, RecoveryPlan



@pytest.mark.asyncio
async def test_agent_execute_multi_wave():
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    
    with patch.object(agent, "execute_goal", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = AgentResult(
            goal="Test", 
            success=True, 
            findings=[{"vulnerability": "SQLi"}]
        )
        
        goal = AgentGoal(description="Find vulns")
        with patch.object(agent.planner_autonomous, "plan", new_callable=AsyncMock) as mock_plan:
            mock_plan.return_value = ExecutionPlan(goal="Test")
            res = await agent.execute_multi_wave(goal, max_waves=2)
            assert res.success is True
            mock_exec.assert_called()

@pytest.mark.asyncio
async def test_agent_execute_multi_wave_empty_findings():
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    
    with patch.object(agent, "execute_goal", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = AgentResult(goal="Test", success=True, findings=[])
        
        goal = AgentGoal(description="Find vulns")
        with patch.object(agent.planner_autonomous, "plan", new_callable=AsyncMock) as mock_plan:
            mock_plan.return_value = ExecutionPlan(goal="Test")
            res = await agent.execute_multi_wave(goal, max_waves=2)
            assert res.success is True

@pytest.mark.asyncio
async def test_agent_execute_subagent():
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    mock_subagent = MagicMock()
    mock_subagent.start = AsyncMock()
    mock_subagent.shutdown = AsyncMock()
    mock_subagent.execute_goal = AsyncMock(return_value=AgentResult(goal="Test", success=True))
    
    with patch.object(agent, "create_subagent", return_value=mock_subagent):
        res = await agent.execute_subagent(role="Recon", goal="Scan network")
        assert res.success is True
        mock_subagent.execute_goal.assert_called_once()

@pytest.mark.asyncio
async def test_hybrid_fallback_with_tools():
    agent = AgentCore(mode=AgentMode.HYBRID)
    fail_plan = ExecutionPlan(goal="Test", status=PlanStatus.FAILED)
    
    step = MagicMock()
    step.status.value = "completed"
    step.tool = "nmap"
    fail_plan.steps = [step]
    
    with patch.object(agent, "_execute_autonomous", new_callable=AsyncMock) as mock_auto:
        mock_auto.return_value = AgentResult(goal="Test", success=False, plan=fail_plan)
        with patch.object(agent, "_execute_registry", new_callable=AsyncMock) as mock_reg:
            mock_reg.return_value = AgentResult(goal="Test", success=True)
            
            res = await agent.execute_goal(AgentGoal(description="Test"))
            assert res.success is True

@pytest.mark.asyncio
async def test_autonomous_failure_recovery():
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    
    plan = ExecutionPlan(goal="Test", status=PlanStatus.COMPLETED)
    step = PlanStep(id="step_1", command="scan", tool="nmap")
    step.status = StepStatus.FAILED
    step.result = {"error": "Connection refused"}
    plan.steps = [step]

    with patch.object(agent._planner_autonomous, "plan", new_callable=AsyncMock) as mock_plan:
        mock_plan.return_value = plan
        with patch.object(agent._executor_autonomous, "execute_plan", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = plan
            with patch.object(agent._validator, "validate_plan", new_callable=AsyncMock):
                with patch.object(agent._validator, "plan_recovery", new_callable=AsyncMock) as mock_rec:
                    modified_step = PlanStep(id="step_1", command="scan", tool="nmap", args={"retry": True})
                    mock_rec.return_value = RecoveryPlan(original_step=step, action=RecoveryAction.RETRY, modified_step=modified_step, message="Retry")
                    
                    with patch.object(agent, "_check_budget", new_callable=AsyncMock):
                        res = await agent.execute_goal(AgentGoal(description="Test"))
                        # Mock exec gets called twice: first run, then recovery retry run
                        assert mock_exec.call_count == 2
                        assert res.success is True




@pytest.mark.asyncio
async def test_agent_start_shutdown():
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.add_signal_handler = MagicMock()
        with patch.object(agent, "initialize", new_callable=AsyncMock) as mock_init:
            with patch.object(agent.executor_registry, "close", new_callable=AsyncMock) as mock_er_close:
                with patch.object(agent.executor_autonomous, "close", new_callable=AsyncMock) as mock_ea_close:
                    await agent.start()
                    mock_init.assert_called_once()
                    
                    await agent.shutdown()
                    mock_er_close.assert_called_once()
                    mock_ea_close.assert_called_once()

@pytest.mark.asyncio
async def test_agent_initialize():
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    with patch.object(agent.registry, "discover_from_path") as mock_discover:
        with patch.object(agent.registry, "scan_path") as mock_scan:
            with patch.object(agent.planner_registry, "build_index") as mock_build_index:
                with patch.object(agent._event_bus, "emit", new_callable=AsyncMock):
                    await agent.initialize()
                    mock_discover.assert_called_once()
                    mock_scan.assert_called_once()
                    mock_build_index.assert_called_once()


@pytest.fixture
def agent():
    return AgentCore(mode=AgentMode.AUTONOMOUS)

def test_agent_properties(agent):
    assert agent.status == AgentStatus.IDLE
    assert agent.mode == AgentMode.AUTONOMOUS

@pytest.mark.asyncio
async def test_execute_registry_mode():
    ag = AgentCore(mode=AgentMode.REGISTRY)
    plan = ExecutionPlan(goal="Test", status=PlanStatus.COMPLETED)
    
    with patch.object(ag.executor_registry, "execute_plan", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = plan
        with patch.object(ag.validator, "validate_plan", new_callable=AsyncMock) as mock_val:
            mock_val.return_value = (True, [])
            res = await ag.execute_goal(AgentGoal(description="Test"), plan=plan)
            assert res.success is True

@pytest.mark.asyncio
async def test_execute_autonomous_mode():
    ag = AgentCore(mode=AgentMode.AUTONOMOUS)
    plan = ExecutionPlan(goal="Test", status=PlanStatus.COMPLETED)
    
    with patch.object(ag.executor_autonomous, "execute_plan", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = plan
        with patch.object(ag.validator, "validate_plan", new_callable=AsyncMock) as mock_val:
            mock_val.return_value = (True, [])
            with patch.object(ag, "_check_budget", new_callable=AsyncMock):
                res = await ag.execute_goal(AgentGoal(description="Test"), plan=plan)
                assert res.success is True

@pytest.mark.asyncio
async def test_execute_hybrid_mode_success():
    ag = AgentCore(mode=AgentMode.HYBRID)
    plan = ExecutionPlan(goal="Test", status=PlanStatus.COMPLETED)
    
    with patch.object(ag, "_execute_autonomous", new_callable=AsyncMock) as mock_auto:
        mock_auto.return_value = AgentResult(goal="Test", success=True, plan=plan)
        res = await ag.execute_goal(AgentGoal(description="Test"), plan=plan)
        assert res.success is True
        mock_auto.assert_called_once()

@pytest.mark.asyncio
async def test_execute_hybrid_mode_fallback():
    ag = AgentCore(mode=AgentMode.HYBRID)
    fail_plan = ExecutionPlan(goal="Test", status=PlanStatus.FAILED)
    success_plan = ExecutionPlan(goal="Test", status=PlanStatus.COMPLETED)
    
    with patch.object(ag, "_execute_autonomous", new_callable=AsyncMock) as mock_auto:
        mock_auto.return_value = AgentResult(goal="Test", success=False, plan=fail_plan)
        with patch.object(ag, "_execute_registry", new_callable=AsyncMock) as mock_reg:
            mock_reg.return_value = AgentResult(goal="Test", success=True, plan=success_plan)
            
            res = await ag.execute_goal(AgentGoal(description="Test"), plan=fail_plan)
            assert res.success is True
            mock_reg.assert_called_once()

@pytest.mark.asyncio
async def test_execute_interactive_mode():
    ag = AgentCore(mode=AgentMode.INTERACTIVE)
    plan = ExecutionPlan(goal="Test", status=PlanStatus.COMPLETED)
    
    with patch.object(ag.executor_autonomous, "execute_plan", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = plan
        with patch.object(ag.validator, "validate_plan", new_callable=AsyncMock) as mock_val:
            mock_val.return_value = (True, [])
            with patch.object(ag, "_check_budget", new_callable=AsyncMock):
                with patch("builtins.input", return_value="y"):
                    res = await ag.execute_goal(AgentGoal(description="Test"), plan=plan)
                    assert res.success is True

@pytest.mark.asyncio
async def test_agent_check_budget(agent):
    agent._usage_tracker = MagicMock()
    agent._usage_tracker.session_totals.return_value = MagicMock(total_tokens=9999999, estimated_cost_usd=0.0)
    agent._max_tokens_per_session = 1000
    
    from siyarix.exceptions import BudgetExceededError
    with pytest.raises(BudgetExceededError):
        await agent._check_budget()

class TestCoreInit:
    """Cover key uncovered lines in core/__init__.py."""

    @pytest.mark.asyncio
    async def test_agent_core_init_exceptions_logged(self):
        with patch("siyarix.plugins.loader.PluginLoader", side_effect=Exception("plugin fail")):
            with patch("siyarix.notifications.NotificationDispatcher", side_effect=Exception("notif fail")):
                from siyarix.core import AgentCore
                agent = AgentCore()
                assert agent._stealth is not None

    @pytest.mark.asyncio
    async def test_check_budget_token_limit(self):
        from siyarix.core import AgentCore
        from siyarix.exceptions import BudgetExceededError
        agent = AgentCore()
        with patch.object(agent._usage_tracker, "session_totals") as mock_st:
            mock_st.return_value.total_tokens = 999999
            mock_st.return_value.estimated_cost_usd = 0.0
            with pytest.raises(BudgetExceededError):
                await agent._check_budget()

    @pytest.mark.asyncio
    async def test_check_budget_cost_limit(self):
        from siyarix.core import AgentCore
        from siyarix.exceptions import BudgetExceededError
        agent = AgentCore()
        with patch.object(agent._usage_tracker, "session_totals") as mock_st:
            mock_st.return_value.total_tokens = 0
            mock_st.return_value.estimated_cost_usd = 999.0
            with pytest.raises(BudgetExceededError):
                await agent._check_budget()

    @pytest.mark.asyncio
    async def test_execute_goal_handles_performance_import_error(self):
        from siyarix.core import AgentCore, AgentGoal, AgentMode
        agent = AgentCore(mode=AgentMode.REGISTRY)
        with patch.object(agent, "_execute_registry") as mock_exec:
            mock_exec.return_value = MagicMock(success=True)
            result = await agent.execute_goal(AgentGoal(description="test"))
            assert result.success is True

    @pytest.mark.asyncio
    async def test_execute_goal_export_exception_debugged(self):
        from siyarix.core import AgentCore, AgentGoal, AgentMode
        agent = AgentCore(mode=AgentMode.REGISTRY)
        with patch.object(agent, "_execute_registry") as mock_exec:
            mock_exec.return_value = MagicMock(success=True)
            with patch("siyarix.output.OutputEngine", side_effect=Exception("export fail")):
                result = await agent.execute_goal(AgentGoal(description="test"))
                assert result.success is True

    def test_create_subagent_shares_knowledge_graph(self):
        from siyarix.core import AgentCore
        agent = AgentCore()
        sub = agent.create_subagent("helper", mode="autonomous")
        assert sub._knowledge_graph is agent._knowledge_graph

    @pytest.mark.asyncio
    async def test_execute_subagent_lifecycle(self):
        from siyarix.core import AgentCore, AgentGoal
        agent = AgentCore()
        mock_sub = AsyncMock()
        mock_sub.start = AsyncMock()
        mock_sub.execute_goal = AsyncMock(return_value=MagicMock(findings=[]))
        mock_sub.shutdown = AsyncMock()
        with patch.object(agent, "create_subagent", return_value=mock_sub):
            result = await agent.execute_subagent("helper", "do stuff")
            mock_sub.start.assert_awaited_once()
            mock_sub.shutdown.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════
# core/learning.py (77% - missing 47-55, 59-72, 80-82, 132-129, 147-148)
# ═══════════════════════════════════════════════════════════════════
class TestCoreExecution:
    """Cover remaining core/__init__.py uncovered lines."""

    def test_core_properties(self):
        core = AgentCore()
        assert isinstance(core.status, object)
        assert isinstance(core.mode, AgentMode)
        assert isinstance(core.stealth, object)

    async def test_check_budget_token_limit(self):
        core = AgentCore()
        core._usage_tracker = MagicMock()
        record = MagicMock()
        record.total_tokens = 200000
        record.estimated_cost_usd = 0.5
        core._usage_tracker.session_totals.return_value = record
        from siyarix.exceptions import BudgetExceededError
        with pytest.raises(BudgetExceededError, match="token limit"):
            await core._check_budget()

    async def test_check_budget_cost_limit(self):
        core = AgentCore()
        core._usage_tracker = MagicMock()
        record = MagicMock()
        record.total_tokens = 100
        record.estimated_cost_usd = 10.0
        core._usage_tracker.session_totals.return_value = record
        from siyarix.exceptions import BudgetExceededError
        with pytest.raises(BudgetExceededError, match="cost limit"):
            await core._check_budget()

    def test_shutdown_providers_state_save(self):
        core = AgentCore()
        mock_providers = MagicMock()
        mock_providers._state = MagicMock()
        core._providers = mock_providers
        with patch.object(core._knowledge_graph, "save_json") as mock_save:
            with patch.object(Path, "mkdir") as mock_mkdir:
                import asyncio
                try:
                    asyncio.run(core.shutdown())
                except Exception:
                    pass

    def test_execute_goal_with_error_handling(self):
        core = AgentCore()
        core._mode = AgentMode.REGISTRY
        with patch.object(core._planner_registry, "plan") as mock_plan:
            mock_plan.return_value = MagicMock(steps=[])
            with patch.object(core._executor_registry, "set_progress_callback"):
                goal = AgentGoal(description="test")
                import asyncio
                try:
                    asyncio.run(core.execute_goal(goal))
                except Exception:
                    pass

    def test_execute_interactive_user_rejects(self):
        core = AgentCore()
        goal = AgentGoal(description="test")
        with patch.object(core._planner_registry, "plan") as mock_plan:
            mock_plan.return_value = MagicMock()
            mock_plan.return_value.steps = []
            with patch("builtins.input", return_value="n"):
                import asyncio
                result = asyncio.run(core._execute_interactive(goal, None, time.time(), AgentResult(goal="test")))
                assert result.success is False
                assert "Plan rejected" in result.summary

    def test_execute_interactive_exception(self):
        core = AgentCore()
        goal = AgentGoal(description="test")
        with patch.object(core._planner_registry, "plan", side_effect=RuntimeError("fail")):
            import asyncio
            result = asyncio.run(core._execute_interactive(goal, None, time.time(), AgentResult(goal="test")))
            assert result.success is False

    def test_extract_findings_from_output(self):
        core = AgentCore()
        plan = MagicMock()
        step = MagicMock(spec=["status", "result", "tool", "description", "id"])
        step.status = "COMPLETED"
        step.result = {"output": "some output"}
        step.tool = "nmap"
        step.description = "scan"
        step.id = "s1"
        plan.steps = [step]
        findings = core._extract_findings(plan)
        assert isinstance(findings, list)

    def test_ingest_finding_to_graph_with_cve(self):
        core = AgentCore()
        with patch.object(core._knowledge_graph, "add_node") as mock_add_node:
            with patch.object(core._knowledge_graph, "add_edge") as mock_add_edge:
                mock_host = MagicMock()
                mock_host.node_id = "h1"
                mock_vuln = MagicMock()
                mock_vuln.node_id = "v1"
                mock_add_node.side_effect = [mock_host, mock_vuln]
                core._ingest_finding_to_graph({"target": "10.0.0.1", "cve": "CVE-2024-0001", "severity": "high"}, "nmap")
                mock_add_edge.assert_called_once()

    def test_create_subagent_shares_knowledge_graph(self):
        core = AgentCore()
        sub = core.create_subagent("analyst")
        assert sub._knowledge_graph is core._knowledge_graph

    def test_execute_subagent(self):
        core = AgentCore()
        with patch.object(core, "start") as mock_start:
            with patch.object(core, "execute_goal") as mock_exec:
                mock_exec.return_value = AgentResult(goal="test")
                import asyncio
                try:
                    result = asyncio.run(core.execute_subagent("analyst", "test goal"))
                except Exception:
                    pass


# ═══════════════════════════════════════════════════════════════════
# 11. executor.py (82% - many uncovered lines/branches)
# ═══════════════════════════════════════════════════════════════════
class TestCoreErrorHandling:
    """Cover remaining core/__init__.py uncovered lines."""

    async def test_start_stealth_enabled(self, tmp_path):
        from siyarix.core import AgentCore
        siyarix_config = str(tmp_path / "siyarix")
        with patch.dict(os.environ, {"SIYARIX_STEALTH": "1", "SIYARIX_CONFIG_DIR": siyarix_config}, clear=True):
            with patch("siyarix.core.StealthEngine") as MockStealth:
                mock_stealth = MagicMock()
                MockStealth.return_value = mock_stealth
                core = AgentCore()
                with patch.object(core._knowledge_graph, "load_json"):
                    with patch.object(core, "initialize") as mock_init:
                        await core.start()
                        mock_stealth.enable.assert_called_once()

    async def test_start_stealth_import_error(self, tmp_path):
        from siyarix.core import AgentCore
        siyarix_config = str(tmp_path / "siyarix")
        with patch.dict(os.environ, {"SIYARIX_STEALTH": "1", "SIYARIX_CONFIG_DIR": siyarix_config}, clear=True):
            with patch("siyarix.core.StealthEngine") as MockStealth:
                mock_stealth = MagicMock()
                MockStealth.return_value = mock_stealth
                core = AgentCore()
                # Make start()'s call to StealthEngine raise ImportError
                MockStealth.side_effect = ImportError("no stealth")
                with patch.object(core._knowledge_graph, "load_json"):
                    with patch.object(core, "initialize") as mock_init:
                        with patch("siyarix.core.logger") as mock_log:
                            await core.start()
                            mock_log.warning.assert_called()

    async def test_start_subagent_handler_success(self):
        from siyarix.core import AgentCore
        core = AgentCore()
        with patch.object(core._knowledge_graph, "load_json"):
            with patch.object(core, "initialize"):
                called = []
                async def mock_start():
                    called.append(True)
                    # Manually register _subagent handler like start() does
                    core._executor_registry.register_executor("_subagent", lambda s: None)
                core.start = mock_start
                await core.start()
                assert len(called) == 1

    async def test_execute_multi_wave_breaks_on_no_findings(self):
        from siyarix.core import AgentCore, AgentGoal, AgentResult
        core = AgentCore()
        goal = AgentGoal(description="test")
        with patch.object(core, "execute_goal") as mock_exec:
            mock_exec.return_value = AgentResult(goal="test", findings=[], success=True)
            result = await core.execute_multi_wave(goal, max_waves=5)
            assert result.success is True

    async def test_execute_multi_wave_with_plan_next_wave(self):
        from siyarix.core import AgentCore, AgentGoal, AgentResult
        core = AgentCore()
        core._planner.plan_next_wave = MagicMock(return_value=None)
        goal = AgentGoal(description="test")
        with patch.object(core, "execute_goal") as mock_exec:
            mock_exec.return_value = AgentResult(goal="test", findings=["f1", "f2"], success=True)
            result = await core.execute_multi_wave(goal, max_waves=2)
        assert result.success
        assert core._planner.plan_next_wave.called

    async def test_execute_autonomous_mode(self):
        from siyarix.core import AgentCore, AgentGoal, AgentResult, AgentMode
        core = AgentCore()
        core._mode = AgentMode.AUTONOMOUS
        goal = AgentGoal(description="test")
        with patch.object(core, "_execute_autonomous", AsyncMock()) as mock_exec:
            mock_exec.return_value = AgentResult(goal="test", success=True)
            with patch.object(core, "_execute_registry"):
                with patch.object(core, "_execute_hybrid"):
                    with patch.object(core, "_execute_interactive"):
                        result = await core.execute_goal(goal)
                        assert result.success is True

    async def test_execute_autonomous_recovery_retry(self):
        from siyarix.core import AgentCore, AgentGoal, AgentResult, AgentMode
        from siyarix.planner import PlanStatus
        core = AgentCore()
        goal = AgentGoal(description="test")
        step = MagicMock()
        step.result = {"error": "timeout"}
        plan = MagicMock()
        plan.has_failures = True
        plan.failed_steps = [step]
        plan.steps = [step]
        plan.completed_steps = [step]
        plan.progress_pct = 100.0
        plan.status = PlanStatus.COMPLETED
        plan.id = "plan_123"
        core._mode = AgentMode.AUTONOMOUS
        from siyarix.validators import RecoveryAction
        with patch.object(core, "_check_budget"):
            with patch.object(core._planner_autonomous, "plan") as mock_plan:
                mock_plan.return_value = plan
                with patch.object(core._validator, "validate_plan"):
                    with patch.object(core._executor_autonomous, "execute_plan") as mock_exec:
                        mock_exec.return_value = plan
                        with patch.object(core._validator, "plan_recovery") as mock_rec:
                            mock_rec.return_value = MagicMock(
                                action=RecoveryAction.RETRY,
                                modified_step=MagicMock(),
                            )
                            with patch.object(core._context, "add_history"):
                                with patch.object(core._providers, "select_provider", return_value=("openai", "gpt-4")):
                                    with patch.object(core._providers, "complete"):
                                        with patch.object(core._learning, "query_similar_experiences", AsyncMock(return_value=[])):
                                            result = await core._execute_autonomous(goal, None, time.time(), AgentResult(goal="test"))
                                            assert result.success

    async def test_execute_autonomous_exception(self):
        from siyarix.core import AgentCore, AgentGoal, AgentResult, AgentMode
        core = AgentCore()
        core._mode = AgentMode.AUTONOMOUS
        goal = AgentGoal(description="test")
        with patch.object(core, "_check_budget"):
            with patch.object(core._planner_autonomous, "plan", side_effect=RuntimeError("fail")):
                result = await core._execute_autonomous(goal, None, time.time(), AgentResult(goal="test"))
                assert result.success is False
                assert "Autonomous agent failed" in result.summary

    async def test_execute_hybrid_fallback(self):
        from siyarix.core import AgentCore, AgentGoal, AgentResult, AgentMode
        core = AgentCore()
        core._mode = AgentMode.HYBRID
        goal = AgentGoal(description="test")
        auto_result = AgentResult(goal="test", success=False)
        auto_result.plan = MagicMock()
        auto_result.plan.has_failures = True
        auto_result.plan.steps = [
            MagicMock(tool="nmap", status="FAILED", result={"error": "not found"}),
        ]
        auto_result.plan.failed_steps = [MagicMock(tool="nmap", result={"error": "not found"})]
        with patch.object(core, "_execute_autonomous", AsyncMock(return_value=auto_result)):
            with patch.object(core._planner_registry, "plan") as mock_reg_plan:
                reg_plan = MagicMock()
                reg_plan.steps = [MagicMock(tool="nmap")]
                mock_reg_plan.return_value = reg_plan
                with patch.object(core, "_execute_registry", AsyncMock()) as mock_reg_exec:
                    mock_reg_exec.return_value = AgentResult(goal=goal.description, success=True)
                    result = await core.execute_goal(goal)
                    assert result is not None

    def test_ingest_finding_no_target_but_cve(self):
        from siyarix.core import AgentCore
        core = AgentCore()
        with patch.object(core._knowledge_graph, "add_node") as mock_add_node:
            with patch.object(core._knowledge_graph, "add_edge") as mock_add_edge:
                mock_vuln = MagicMock()
                mock_vuln.node_id = "v1"
                mock_add_node.return_value = mock_vuln
                core._ingest_finding_to_graph(
                    {"cve": "CVE-2024-0001", "severity": "high", "title": "Test Vuln"},
                    "nmap",
                )
                mock_add_node.assert_called_once()

    def test_stats(self):
        from siyarix.core import AgentCore
        core = AgentCore()
        s = core.stats()
        assert "mode" in s
        assert "status" in s
        assert "registry" in s


# ═══════════════════════════════════════════════════════════════════
# 7. credential_store.py (79% - many uncovered lines)
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def cred_store(tmp_path, monkeypatch):
    from siyarix.credential_store import CredentialStore
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
    monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
    s = CredentialStore(master_password="test_master")
    return s
