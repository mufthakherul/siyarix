# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for engine/executor.py — ExecutionEngine (618 stmts, ~42% covered)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.engine.executor import ExecutionEngine
from siyarix.engine.steps import EngineResult, ExecutionMode
from siyarix.engine_types import StepResult, StepStatus
from siyarix.planner import ExecutionPlan, ExecutionStep, StepType
from siyarix.tool_registry import ToolInfo, ToolRegistry
from siyarix.kill_switch import KillSwitch, KillSwitchState


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_registry():
    reg = MagicMock(spec=ToolRegistry)
    t1 = ToolInfo(name="nmap", binary="nmap", path="/usr/bin/nmap", version="7.94",
                  capabilities=["port_scan"], category="recon", description="", default_args=[])
    t2 = ToolInfo(name="nuclei", binary="nuclei", path="/usr/bin/nuclei", version="3.1",
                  capabilities=["vuln_scan"], category="vuln", description="", default_args=[])
    reg.discover.return_value = [t1, t2]
    return reg


@pytest.fixture
def engine(mock_registry):
    with patch("siyarix.engine.executor.ToolRegistry", return_value=mock_registry), \
         patch("siyarix.engine.executor.KillSwitch"), \
         patch("siyarix.engine.executor.AsyncWorkerPool"), \
         patch("siyarix.engine.executor.DynamicResolver"), \
         patch("siyarix.engine.executor.ToolExecutor"), \
         patch("siyarix.engine.executor.TaskPlanner"):
            eng = ExecutionEngine(config={"fast_discovery": True})
            eng._kill_switch = MagicMock(spec=KillSwitch)
            eng._kill_switch.state = KillSwitchState.ARMED
            eng._pool = MagicMock()
            eng._resolver = MagicMock()
            eng._executor = MagicMock()
            eng._graph = MagicMock()
            yield eng


def make_step(step_id="s1", step_type=StepType.TOOL_RUN, tool="nmap",
              args=None, target="10.0.0.1", depends_on=None,
              command=None, description="test step"):
    return ExecutionStep(
        id=step_id, step_type=step_type, tool=tool, args=args or [],
        target=target, depends_on=depends_on or [], command=command,
        description=description,
    )


def make_sr(step_id="s1", status=StepStatus.SUCCESS, output="ok", error="",
            findings=None, retry_count=0, exit_code=None, duration_ms=0.0):
    return StepResult(step_id=step_id, status=status, output=output, error=error,
                      findings=findings or [], retry_count=retry_count,
                      exit_code=exit_code, duration_ms=duration_ms)


# ---------------------------------------------------------------------------
# Initialization & Properties
# ---------------------------------------------------------------------------

class TestInit:
    def test_default_mode(self, engine):
        assert engine.mode == ExecutionMode.INTEGRATED

    def test_discovered_tools(self, engine):
        assert len(engine.discovered_tools) == 2

    def test_kill_switch_property(self, engine):
        assert engine.kill_switch is not None


# ---------------------------------------------------------------------------
# _on_kill
# ---------------------------------------------------------------------------

class TestOnKill:
    def test_on_kill_creates_task(self, engine):
        engine._pool = MagicMock()
        engine._on_kill()
        engine._pool.cancel_pending.assert_called_once()


# ---------------------------------------------------------------------------
# _refresh_tools
# ---------------------------------------------------------------------------

class TestRefreshTools:
    def test_refresh_tools(self, engine, mock_registry):
        engine._registry = mock_registry
        engine._refresh_tools()
        assert mock_registry.discover.call_count >= 1
        assert engine._resolver is not None


# ---------------------------------------------------------------------------
# _build_context
# ---------------------------------------------------------------------------

class TestBuildContext:
    def test_build_context_returns_dict(self, engine):
        ctx = engine._build_context()
        assert isinstance(ctx, dict)
        assert "available_tools" in ctx
        assert "mode" in ctx


# ---------------------------------------------------------------------------
# _check_dependencies
# ---------------------------------------------------------------------------

class TestCheckDependencies:
    def test_no_deps(self, engine):
        step = make_step(depends_on=[])
        assert engine._check_dependencies(step) is True

    def test_dep_met(self, engine):
        engine._completed_steps["s0"] = make_sr("s0", StepStatus.SUCCESS)
        step = make_step(depends_on=["s0"])
        assert engine._check_dependencies(step) is True

    def test_dep_missing(self, engine):
        step = make_step(depends_on=["s0"])
        assert engine._check_dependencies(step) is False

    def test_dep_failed(self, engine):
        engine._completed_steps["s0"] = make_sr("s0", StepStatus.FAILED)
        step = make_step(depends_on=["s0"])
        assert engine._check_dependencies(step) is False

    def test_dep_skipped_allowed(self, engine):
        engine._completed_steps["s0"] = make_sr("s0", StepStatus.SKIPPED)
        step = make_step(depends_on=["s0"])
        assert engine._check_dependencies(step) is True


# ---------------------------------------------------------------------------
# _evaluate_condition
# ---------------------------------------------------------------------------

class TestEvaluateCondition:
    def test_not_condition(self, engine):
        engine._completed_steps["s1"] = make_sr("s1", StepStatus.FAILED)
        assert engine._evaluate_condition("not (s1.success)") is True

    def test_not_without_paren(self, engine):
        engine._completed_steps["s1"] = make_sr("s1", StepStatus.FAILED)
        assert engine._evaluate_condition("not s1.success") is True

    def test_dot_success_true(self, engine):
        engine._completed_steps["s1"] = make_sr("s1", StepStatus.SUCCESS)
        assert engine._evaluate_condition("s1.success") is True

    def test_dot_success_false(self, engine):
        engine._completed_steps["s1"] = make_sr("s1", StepStatus.FAILED)
        assert engine._evaluate_condition("s1.success") is False

    def test_dot_failed_true(self, engine):
        engine._completed_steps["s1"] = make_sr("s1", StepStatus.FAILED)
        assert engine._evaluate_condition("s1.failed") is True

    def test_findings_count_gt_zero(self, engine):
        engine._completed_steps["s1"] = make_sr("s1", findings=[{"sev": "high"}])
        assert engine._evaluate_condition("findings.count > 0") is True

    def test_findings_count_zero(self, engine):
        assert engine._evaluate_condition("findings.count > 0") is False

    def test_unknown_condition_defaults_true(self, engine):
        assert engine._evaluate_condition("some_unknown_condition") is True


# ---------------------------------------------------------------------------
# plan()
# ---------------------------------------------------------------------------

class TestPlan:
    @pytest.mark.asyncio
    async def test_plan_registry_mode(self, engine):
        engine._mode = ExecutionMode.REGISTRY
        engine._planner = MagicMock()
        engine._planner.plan = AsyncMock(return_value=ExecutionPlan(
            steps=[make_step()], raw_instruction="test"))
        plan = await engine.plan("test instruction")
        assert plan is not None
        engine._planner.plan.assert_called_once()
        args = engine._planner.plan.call_args[0]
        assert args[0] == "test instruction"
        assert args[2] == "static"

    @pytest.mark.asyncio
    async def test_plan_autonomous_mode(self, engine):
        engine._mode = ExecutionMode.AUTONOMOUS
        engine._planner = MagicMock()
        engine._planner.plan = AsyncMock(return_value=ExecutionPlan(
            steps=[make_step()], raw_instruction="test"))
        plan = await engine.plan("test instruction")
        assert plan is not None
        args = engine._planner.plan.call_args[0]
        assert args[2] == "autonomous"

    @pytest.mark.asyncio
    async def test_plan_integrated_mode(self, engine):
        engine._planner = MagicMock()
        engine._planner.plan = AsyncMock(return_value=ExecutionPlan(
            steps=[make_step()], raw_instruction="test"))
        plan = await engine.plan("test instruction")
        assert plan is not None
        args = engine._planner.plan.call_args[0]
        assert args[2] is None


# ---------------------------------------------------------------------------
# execute()
# ---------------------------------------------------------------------------

class TestExecute:
    @pytest.mark.asyncio
    async def test_execute_kill_switch_triggered(self, engine):
        engine._kill_switch.state = KillSwitchState.TRIGGERED
        result = await engine.execute("test", interactive=False)
        assert isinstance(result, EngineResult)
        assert result.total_duration_ms == 0.0

    @pytest.mark.asyncio
    async def test_execute_dry_run(self, engine):
        with patch.object(engine, "plan") as mock_plan:
            mock_plan.return_value = ExecutionPlan(
                steps=[make_step()], raw_instruction="test")
            result = await engine.execute("test", interactive=False, dry_run=True)
            assert isinstance(result, EngineResult)
            assert result.plan is not None
            assert len(result.step_results) == 0

    @pytest.mark.asyncio
    async def test_execute_no_steps(self, engine):
        with patch.object(engine, "plan") as mock_plan:
            mock_plan.return_value = ExecutionPlan(steps=[], raw_instruction="test")
            result = await engine.execute("test", interactive=False)
            assert isinstance(result, EngineResult)
            assert len(result.step_results) == 0

# ---------------------------------------------------------------------------
# _execute_plan
# ---------------------------------------------------------------------------

class TestExecutePlan:
    @pytest.mark.asyncio
    async def test_execute_plan_all_done(self, engine):
        plan = ExecutionPlan(steps=[make_step("s1")], raw_instruction="test")
        engine._pool.submit = MagicMock()

        async def fake_submit(fn, step):
            return make_sr("s1", StepStatus.SUCCESS, output="done")
        engine._pool.submit = fake_submit

        result = await engine._execute_plan(plan, None, False, None, None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_execute_plan_blocked_deps(self, engine):
        s1 = make_step("s1", depends_on=["missing"])
        plan = ExecutionPlan(steps=[s1], raw_instruction="test")
        result = await engine._execute_plan(plan, None, False, None, None)
        assert any(r.status == StepStatus.BLOCKED for r in result.step_results)


# ---------------------------------------------------------------------------
# _execute_step_with_retry
# ---------------------------------------------------------------------------

class TestExecuteStepWithRetry:
    @pytest.mark.asyncio
    async def test_no_retry_for_report_type(self, engine):
        step = make_step(step_type=StepType.REPORT)
        engine._executor.execute_step = AsyncMock(
            return_value=make_sr("s1", StepStatus.SUCCESS))
        sr = await engine._execute_step_with_retry(step, False)
        assert sr.status == StepStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_retry_on_transient_failure(self, engine):
        step = make_step(step_type=StepType.TOOL_RUN)
        engine._executor.execute_step = AsyncMock()
        engine._executor.execute_step.side_effect = [
            make_sr("s1", StepStatus.FAILED, error="connection reset"),
            make_sr("s1", StepStatus.FAILED, error="connection reset"),
            make_sr("s1", StepStatus.SUCCESS, output="ok"),
        ]
        with patch("siyarix.engine.executor._is_transient_error_impl", return_value=True), \
             patch("siyarix.engine.executor.asyncio.sleep", AsyncMock()):
            sr = await engine._execute_step_with_retry(step, False)
        assert sr.status == StepStatus.SUCCESS
        assert sr.retry_count <= 3

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self, engine):
        step = make_step(step_type=StepType.TOOL_RUN)
        engine._executor.execute_step = AsyncMock(
            return_value=make_sr("s1", StepStatus.FAILED, error="timeout"))
        with patch("siyarix.engine.executor._is_transient_error_impl", return_value=True), \
             patch("siyarix.engine.executor.asyncio.sleep", AsyncMock()):
            sr = await engine._execute_step_with_retry(step, False)
        assert sr.status == StepStatus.FAILED

    @pytest.mark.asyncio
    async def test_exception_during_execute(self, engine):
        step = make_step(step_type=StepType.TOOL_RUN)
        engine._executor.execute_step = AsyncMock(side_effect=RuntimeError("boom"))
        with patch("siyarix.engine.executor._is_transient_error_impl", return_value=False):
            sr = await engine._execute_step_with_retry(step, False)
        assert sr.status == StepStatus.FAILED


# ---------------------------------------------------------------------------
# _run_tool_step
# ---------------------------------------------------------------------------

class TestRunToolStep:
    @pytest.mark.asyncio
    async def test_run_tool_step_success(self, engine):
        step = make_step(tool="nmap", args=["-sV", "10.0.0.1"])
        engine._resolver.resolve.return_value = MagicMock(is_safe=True, warnings=[])
        engine._executor.execute_step = AsyncMock(
            return_value=make_sr("s1", StepStatus.SUCCESS, findings=[{"severity": "high"}]))
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="-sV 10.0.0.1"):
            sr = await engine._run_tool_step(step, False)
        assert sr.status == StepStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_run_tool_step_forbidden(self, engine):
        step = make_step(tool="nmap", args=["-sV"])
        engine._resolver.resolve.return_value = MagicMock(is_safe=True, warnings=[])
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="__forbidden__"):
            sr = await engine._run_tool_step(step, False)
        assert sr.status == StepStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_run_tool_step_not_found_installs(self, engine):
        step = make_step(tool="nmap", args=["-sV"])
        resolved = MagicMock(is_safe=False, warnings=["nmap not found on PATH"])
        engine._resolver.resolve.return_value = resolved
        with patch.object(engine, "_try_install_tool", AsyncMock(return_value=True)), \
             patch("siyarix.engine.executor._check_permission_gate",
                   return_value="-sV"), \
             patch("siyarix.engine.executor.DynamicResolver"):
            engine._executor.execute_step = AsyncMock(
                return_value=make_sr("s1", StepStatus.SUCCESS))
            sr = await engine._run_tool_step(step, False)
        assert sr.status == StepStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_run_tool_session_logger(self, engine):
        step = make_step(tool="nmap", args=["-sV"])
        engine._resolver.resolve.return_value = MagicMock(is_safe=True, warnings=[])
        engine._session_logger = MagicMock()
        engine._current_log_session_id = "sess_1"
        engine._executor.execute_step = AsyncMock(
            return_value=make_sr("s1", StepStatus.SUCCESS))
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="-sV"):
            sr = await engine._run_tool_step(step, False)
        assert sr.status == StepStatus.SUCCESS
        engine._session_logger.add_command.assert_called()
        engine._session_logger.track_tool_usage.assert_called()


# ---------------------------------------------------------------------------
# _run_shell_step
# ---------------------------------------------------------------------------

class TestRunShellStep:
    @pytest.mark.asyncio
    async def test_run_shell_step_success(self, engine):
        step = make_step(step_type=StepType.SHELL_CMD, command="echo hello")
        engine._resolver.resolve.return_value = MagicMock(is_safe=True, warnings=[])
        engine._executor.execute_step = AsyncMock(
            return_value=make_sr("s1", StepStatus.SUCCESS, output="hello"))
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="echo hello"):
            sr = await engine._run_shell_step(step, False)
        assert sr.status == StepStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_run_shell_step_empty_command(self, engine):
        step = make_step(step_type=StepType.SHELL_CMD, command="")
        sr = await engine._run_shell_step(step, False)
        assert sr.status == StepStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_run_shell_step_forbidden(self, engine):
        step = make_step(step_type=StepType.SHELL_CMD, command="dangerous")
        engine._resolver.resolve.return_value = MagicMock(is_safe=True, warnings=[])
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="__forbidden__"):
            sr = await engine._run_shell_step(step, False)
        assert sr.status == StepStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_run_shell_step_not_found_installs(self, engine):
        step = make_step(step_type=StepType.SHELL_CMD, command="hydra -l admin")
        resolved = MagicMock(is_safe=False, warnings=["hydra not found on PATH"])
        engine._resolver.resolve.return_value = resolved
        with patch.object(engine, "_try_install_tool", AsyncMock(return_value=True)), \
             patch("siyarix.engine.executor._check_permission_gate",
                   return_value="hydra -l admin"), \
             patch("siyarix.engine.executor.DynamicResolver"):
            engine._executor.execute_step = AsyncMock(
                return_value=make_sr("s1", StepStatus.SUCCESS))
            sr = await engine._run_shell_step(step, False)
        assert sr.status == StepStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_run_shell_session_logger(self, engine):
        step = make_step(step_type=StepType.SHELL_CMD, command="echo test")
        engine._resolver.resolve.return_value = MagicMock(is_safe=True, warnings=[])
        engine._session_logger = MagicMock()
        engine._current_log_session_id = "sess_1"
        engine._executor.execute_step = AsyncMock(
            return_value=make_sr("s1", StepStatus.SUCCESS, exit_code=0))
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="echo test"):
            await engine._run_shell_step(step, False)
        engine._session_logger.add_command.assert_called()
        engine._session_logger.track_tool_usage.assert_called()


# ---------------------------------------------------------------------------
# _adapt_plan_on_step_result (Dynamic Plan Mutator)
# ---------------------------------------------------------------------------

class TestAdaptPlanOnStepResult:
    def test_nmap_host_down_injects_pn_retry(self, engine):
        step = make_step("s1", tool="nmap", args=["-sV"])
        sr = make_sr("s1", StepStatus.FAILED, error="Host seems down")
        pending = [make_step("s2", depends_on=["s1"])]
        plan = ExecutionPlan(steps=[step, pending[0]], raw_instruction="test")
        engine._adapt_plan_on_step_result(step, sr, plan, pending)
        assert len(pending) > 1
        assert pending[0].id == "s1_retry_pn"
        assert "-Pn" in pending[0].args

    def test_nikto_failure_injects_nuclei_fallback(self, engine):
        step = make_step("s1", tool="nikto")
        sr = make_sr("s1", StepStatus.FAILED)
        pending = [make_step("s2", depends_on=["s1"])]
        plan = ExecutionPlan(steps=[step, pending[0]], raw_instruction="test")
        engine._adapt_plan_on_step_result(step, sr, plan, pending)
        assert pending[0].id == "s1_fallback_nuclei"

    def test_gobuster_zero_findings_injects_nikto(self, engine):
        step = make_step("s1", tool="gobuster")
        sr = make_sr("s1", StepStatus.SUCCESS, findings=[])
        pending = [make_step("s2", depends_on=["s1"])]
        plan = ExecutionPlan(steps=[step, pending[0]], raw_instruction="test")
        engine._adapt_plan_on_step_result(step, sr, plan, pending)
        assert pending[0].id == "s1_fallback_nikto"

    def test_shell_cmd_permission_denied_injects_priv_check(self, engine):
        step = make_step("s1", step_type=StepType.SHELL_CMD, command="access")
        sr = make_sr("s1", StepStatus.FAILED, output="Permission denied")
        pending = []
        plan = ExecutionPlan(steps=[step], raw_instruction="test")
        engine._adapt_plan_on_step_result(step, sr, plan, pending)
        assert pending[0].id == "s1_priv_check"
        assert pending[0].step_type == StepType.SHELL_CMD

    def test_no_mutation_normal_case(self, engine):
        step = make_step("s1", tool="nmap")
        sr = make_sr("s1", StepStatus.SUCCESS, findings=[{"sev": "low"}])
        pending = [make_step("s2")]
        plan = ExecutionPlan(steps=[step, pending[0]], raw_instruction="test")
        engine._adapt_plan_on_step_result(step, sr, plan, pending)
        assert len(pending) == 1


# ---------------------------------------------------------------------------
# _replan_from_feedback
# ---------------------------------------------------------------------------

class TestReplanFromFeedback:
    @pytest.mark.asyncio
    async def test_replan_skipped_if_max_reached(self, engine):
        engine._replan_attempts = engine._max_replans
        step = make_step("s1")
        sr = make_sr("s1", StepStatus.FAILED)
        plan = ExecutionPlan(steps=[step], raw_instruction="test")
        await engine._replan_from_feedback(step, sr, plan, [])
        assert engine._replan_attempts == engine._max_replans

    @pytest.mark.asyncio
    async def test_replan_skipped_on_success_with_findings(self, engine):
        step = make_step("s1")
        sr = make_sr("s1", StepStatus.SUCCESS, findings=[{"sev": "low"}])
        plan = ExecutionPlan(steps=[step], raw_instruction="test")
        await engine._replan_from_feedback(step, sr, plan, [])
        assert engine._replan_attempts == 0

    @pytest.mark.asyncio
    async def test_replan_injects_steps(self, engine):
        step = make_step("s1")
        sr = make_sr("s1", StepStatus.FAILED)
        plan = ExecutionPlan(steps=[step], raw_instruction="test")
        pending = []
        engine._planner.replan = AsyncMock(return_value=ExecutionPlan(
            steps=[make_step("adaptive_1", tool="nuclei")],
            raw_instruction="test",
        ))
        await engine._replan_from_feedback(step, sr, plan, pending)
        assert len(pending) > 0
        assert engine._replan_attempts == 1

    @pytest.mark.asyncio
    async def test_replan_empty_response(self, engine):
        step = make_step("s1")
        sr = make_sr("s1", StepStatus.FAILED)
        plan = ExecutionPlan(steps=[step], raw_instruction="test")
        pending = []
        engine._planner.replan = AsyncMock(return_value=None)
        await engine._replan_from_feedback(step, sr, plan, pending)
        assert len(pending) == 0


# ---------------------------------------------------------------------------
# _record_step_feedback
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# resume
# ---------------------------------------------------------------------------

class TestResume:
    @pytest.mark.asyncio
    async def test_resume_not_implemented(self, engine):
        result = await engine.resume("any_plan_id", interactive=False)
        assert result.success is True


# ---------------------------------------------------------------------------
# _plan_from_dict
# ---------------------------------------------------------------------------

class TestPlanFromDict:
    def test_reconstructs_plan(self, engine):
        data = {
            "steps": [{
                "id": "s1", "step_type": "tool_run", "tool": "nmap",
                "command": None, "args": ["-sV"], "target": "10.0.0.1",
                "depends_on": [], "condition": None, "timeout": 300,
                "description": "scan", "metadata": {},
            }],
            "source": "registry", "confidence": 0.9, "raw_instruction": "test",
        }
        plan = engine._plan_from_dict(data)
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "nmap"
        assert plan.confidence == 0.9

    def test_handles_bad_step_type(self, engine):
        data = {
            "steps": [{"id": "s1", "step_type": "invalid_type"}],
            "source": "test", "confidence": 0.5, "raw_instruction": "test",
        }
        plan = engine._plan_from_dict(data)
        assert plan.steps[0].step_type == StepType.TOOL_RUN


# ---------------------------------------------------------------------------
# _try_install_tool
# ---------------------------------------------------------------------------

class TestTryInstallTool:
    @pytest.mark.asyncio
    async def test_no_valid_installers(self, engine):
        with patch("siyarix.engine.executor.shutil.which", return_value=None), \
             patch("siyarix.engine.executor.platform.system", return_value="linux"):
            result = await engine._try_install_tool("unknown_tool")
        assert result is False

    @pytest.mark.asyncio
    async def test_python_tool(self, engine):
        with patch("siyarix.engine.executor.shutil.which", return_value="/usr/bin/pip"), \
             patch("siyarix.engine.executor.platform.system", return_value="linux"), \
             patch("siyarix.output.output.prompt_confirm", return_value=True), \
             patch("siyarix.engine.run_tool_complete",
                   AsyncMock(return_value=MagicMock(exit_code=0))), \
             patch.object(engine, "_refresh_tools"):
            result = await engine._try_install_tool("shodan")
        assert result is True

    @pytest.mark.asyncio
    async def test_user_declines(self, engine):
        with patch("siyarix.engine.executor.shutil.which", return_value="/usr/bin/apt-get"), \
             patch("siyarix.engine.executor.platform.system", return_value="linux"), \
             patch("siyarix.output.output.prompt_confirm", return_value=False):
            result = await engine._try_install_tool("nmap")
        assert result is False

    @pytest.mark.asyncio
    async def test_successful_install(self, engine):
        mock_result = MagicMock(exit_code=0)
        with patch("siyarix.engine.executor.shutil.which", return_value="/usr/bin/apt-get"), \
             patch("siyarix.engine.executor.platform.system", return_value="linux"), \
             patch("siyarix.output.output.prompt_confirm", return_value=True), \
             patch("siyarix.engine.run_tool_complete",
                   AsyncMock(return_value=mock_result)), \
             patch.object(engine, "_refresh_tools"):
            result = await engine._try_install_tool("nmap")
        assert result is True

    @pytest.mark.asyncio
    async def test_installer_fails_then_succeeds(self, engine):
        mock_fail = MagicMock(exit_code=1)
        mock_ok = MagicMock(exit_code=0)
        results = [mock_fail, mock_ok]
        with patch("siyarix.engine.executor.shutil.which", return_value="/usr/bin/apt-get"), \
             patch("siyarix.engine.executor.platform.system", return_value="linux"), \
             patch("siyarix.output.output.prompt_confirm", return_value=True), \
             patch("siyarix.engine.run_tool_complete",
                   AsyncMock(side_effect=lambda *a, **kw: results.pop(0))), \
             patch.object(engine, "_refresh_tools"):
            result = await engine._try_install_tool("nmap")
        assert result is True


# ---------------------------------------------------------------------------
# _persist_step
# ---------------------------------------------------------------------------

class TestPersistStep:
    def test_persists_with_store(self, engine):
        store = MagicMock()
        sr = make_sr("s1")
        engine._persist_step(store, "plan_1", sr)
        store.upsert_step_execution.assert_called_once()

    def test_no_store(self, engine):
        sr = make_sr("s1")
        engine._persist_step(None, None, sr)  # should not raise


# ---------------------------------------------------------------------------
# execute_objective
# ---------------------------------------------------------------------------

class TestExecuteObjective:
    @pytest.mark.asyncio
    async def test_execute_objective_not_implemented(self, engine):
        result = await engine.execute_objective("test objective", target="10.0.0.1")
        assert result.get("status") == "unavailable"


# ---------------------------------------------------------------------------
# compress_context
# ---------------------------------------------------------------------------

class TestCompressContext:
    def test_compress_context_delegates(self, engine):
        with patch.object(engine, "compress_context") as mock_cc:
            mock_cc.return_value = {"compressed": True}
            result = engine.compress_context({"foo": "bar"})
            assert result == {"compressed": True}


# ---------------------------------------------------------------------------
# _apply_permission_gate
# ---------------------------------------------------------------------------

class TestApplyPermissionGate:
    @pytest.mark.asyncio
    async def test_permission_gate_passes(self, engine):
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="allowed"):
            result = await engine._apply_permission_gate(
                make_step(), "test_value", "test_display", False)
        assert result == "allowed"

    @pytest.mark.asyncio
    async def test_permission_gate_blocks(self, engine):
        with patch("siyarix.engine.executor._check_permission_gate",
                   return_value="__forbidden__"):
            result = await engine._apply_permission_gate(
                make_step(), "bad_value", "bad_display", False)
        assert result == "__forbidden__"


# ---------------------------------------------------------------------------
# _display_plan / _display_summary (coverage only, no output assertions)
# ---------------------------------------------------------------------------

class TestDisplay:
    def test_display_plan(self, engine):
        plan = ExecutionPlan(steps=[make_step()], raw_instruction="test",
                             source="registry", confidence=0.9)
        with patch("siyarix.engine.executor.console"):
            engine._display_plan(plan)

    def test_display_summary(self, engine):
        plan = ExecutionPlan(steps=[make_step()], raw_instruction="test")
        result = EngineResult(plan=plan, mode=engine._mode)
        result.step_results = [make_sr("s1")]
        result.total_duration_ms = 1000.0
        with patch("siyarix.engine.executor.console"):
            engine._display_summary(result)


# ---------------------------------------------------------------------------
# _execute_step routing
# ---------------------------------------------------------------------------

class TestExecuteStep:
    @pytest.mark.asyncio
    async def test_execute_tool_step(self, engine):
        step = make_step(step_type=StepType.TOOL_RUN, tool="nmap")
        with patch.object(engine, "_run_tool_step", AsyncMock(
                return_value=make_sr("s1"))):
            sr = await engine._execute_step(step, False)
            assert sr is not None

    @pytest.mark.asyncio
    async def test_execute_shell_step(self, engine):
        step = make_step(step_type=StepType.SHELL_CMD, command="echo hi")
        with patch.object(engine, "_run_shell_step", AsyncMock(
                return_value=make_sr("s1"))):
            sr = await engine._execute_step(step, False)
            assert sr is not None

    @pytest.mark.asyncio
    async def test_execute_analysis_step(self, engine):
        step = make_step(step_type=StepType.ANALYSIS)
        engine._executor.execute_step = AsyncMock(return_value=make_sr("s1"))
        sr = await engine._execute_step(step, False)
        assert sr is not None


# ---------------------------------------------------------------------------
# _calculate_backoff_delay
# ---------------------------------------------------------------------------

class TestBackoffDelay:
    @pytest.mark.asyncio
    async def test_backoff_delegates(self, engine):
        with patch("siyarix.engine.executor._calculate_backoff_delay_impl",
                   AsyncMock(return_value=2.5)):
            delay = await engine._calculate_backoff_delay(1)
            assert delay == 2.5


# ---------------------------------------------------------------------------
# _is_transient_error
# ---------------------------------------------------------------------------

class TestIsTransientError:
    def test_delegates(self, engine):
        with patch("siyarix.engine.executor._is_transient_error_impl",
                   return_value=True):
            assert engine._is_transient_error("timeout") is True
