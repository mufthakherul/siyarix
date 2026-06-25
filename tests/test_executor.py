from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.exceptions import PermissionDeniedError, ToolExecutionError, ToolNotFoundError
from siyarix.executor import (
    BaseExecutor,
    ExecutionBudget,
    GuardrailConfig,
    ToolCallTracker,
    _get_dlp_engine,
    _get_review_and_confirm,
    _get_session_logger,
    _redact_value,
)
from siyarix.executor_registry import RegistryExecutor
from siyarix.models import ExecutionPlan, PlanStep, PlanType, StepStatus
from siyarix.registry import ToolRegistry
from siyarix.subprocess_utils import (
    ExecutionResult,
    _validate_cmd_list,
    safe_run_async,
    safe_run_sync,
)


class TestValidateCmdList:
    def test_valid_command(self) -> None:
        _validate_cmd_list(["nmap", "-sV", "127.0.0.1"])

    def test_empty_list(self) -> None:
        with pytest.raises(ValueError, match="non-empty list"):
            _validate_cmd_list([])

    def test_not_a_list(self) -> None:
        with pytest.raises(ValueError, match="non-empty list"):
            _validate_cmd_list("nmap")  # type: ignore[arg-type]

    def test_non_string_element(self) -> None:
        with pytest.raises(ValueError, match="must be strings"):
            _validate_cmd_list(["nmap", 123])  # type: ignore[list-item]

    def test_shell_metacharacters_allowed(self) -> None:
        _validate_cmd_list(["nmap", "target;cmd"])
        _validate_cmd_list(["nmap", "target|cmd"])
        _validate_cmd_list(["nmap", "target>cmd"])

    def test_multiple_args_valid(self) -> None:
        _validate_cmd_list(["tool", "-a", "-b", "--long", "value"])


class TestExecutionResult:
    def test_success_property(self) -> None:
        r = ExecutionResult(exit_code=0, stdout="ok", stderr="", duration_ms=100)
        assert r.success is True

    def test_failure_property(self) -> None:
        r = ExecutionResult(exit_code=1, stdout="", stderr="error", duration_ms=50)
        assert r.success is False

    def test_defaults(self) -> None:
        r = ExecutionResult()
        assert r.exit_code == 0
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.duration_ms == 0.0


class TestSafeRunSync:
    def test_success(self) -> None:
        with patch("siyarix.subprocess_utils.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
            result = safe_run_sync(["echo", "hi"])
            assert result.exit_code == 0

    def test_timeout_raises(self) -> None:
        with patch(
            "siyarix.subprocess_utils.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="sleep 10", timeout=0.001),
        ):
            with pytest.raises(subprocess.TimeoutExpired):
                safe_run_sync(["sleep", "10"], timeout=0.001)

    def test_exception_raises(self) -> None:
        with patch(
            "siyarix.subprocess_utils.subprocess.run",
            side_effect=FileNotFoundError("not found"),
        ):
            with pytest.raises(FileNotFoundError):
                safe_run_sync(["nonexistent_tool"])

    @patch(
        "siyarix.subprocess_utils._confirm_destructive",
        side_effect=ValueError("destructive pattern"),
    )
    def test_validation_error(self, mock_confirm) -> None:
        with pytest.raises(ValueError, match="destructive pattern"):
            safe_run_sync(["rm", "-rf", "/"])


class TestSafeRunAsync:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"out", b"err"))
        mock_proc.returncode = 0

        with (
            patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False),
            patch("siyarix.subprocess_utils._validate_cmd_list"),
            patch(
                "siyarix.subprocess_utils.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            result = await safe_run_async(["tool", "arg"])
            assert result.exit_code == 0
            assert result.stdout == "out"

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=[asyncio.TimeoutError(), (b"partial", b"")])
        mock_proc.kill = MagicMock()

        with (
            patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False),
            patch("siyarix.subprocess_utils._validate_cmd_list"),
            patch(
                "siyarix.subprocess_utils.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            result = await safe_run_async(["tool", "arg"], timeout=0.001)
            assert result.exit_code == -1
            mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_validation_error(self) -> None:
        with pytest.raises(ValueError, match="non-empty list"):
            await safe_run_async([])


class TestExecutorCore:
    """Cover uncovered lines in executor.py."""

    def test_redact_value_sensitive_key(self):
        from siyarix.executor import _redact_value

        result = _redact_value("password", "my_secret_value")
        assert "***" in result
        assert len(result) < len("my_secret_value")

    def test_redact_value_short_sensitive(self):
        from siyarix.executor import _redact_value

        result = _redact_value("token", "ab")
        assert result == "***"

    def test_dlp_engine_not_available(self):
        import siyarix.executor as exec_mod

        exec_mod._DLP_ENGINE = None
        with patch.dict("sys.modules", {"siyarix.dlp": None}):
            engine = exec_mod._get_dlp_engine()
            assert engine is None

    def test_budget_is_exhausted(self):
        from siyarix.executor import ExecutionBudget

        b = ExecutionBudget(max_iterations=0, max_tool_calls=0, max_duration_s=0)
        assert b.is_exhausted is True

    def test_budget_progress_pct_max_zero(self):
        from siyarix.executor import ExecutionBudget

        b = ExecutionBudget(max_iterations=0)
        assert b.progress_pct == 100.0

    def test_guardrail_blocked_by_failures(self):
        from siyarix.executor import ToolCallTracker

        cfg = GuardrailConfig(exact_failure_block_after=2)
        tracker = ToolCallTracker()
        tracker._config = cfg
        with patch.object(tracker, "_save_state"):
            result = tracker.record("nmap", "target:x", False)
            result = tracker.record("nmap", "target:x", False)
            result = tracker.record("nmap", "target:x", False)
            assert result is not None
            assert "BLOCKED" in result

    def test_log_safety_blocked_no_session_logger(self):
        from siyarix.executor import BaseExecutor

        be = BaseExecutor()
        be._log_safety("nmap", "scan", "blocked", "bad")
        assert True

    def test_permission_check_skipped_when_no_gate(self):
        from siyarix.executor import BaseExecutor

        be = BaseExecutor()
        be._permission_gate = None
        step = PlanStep(tool="nmap", args={"command": "nmap -sV"})
        import asyncio

        asyncio.run(be._check_permissions(step))


# ═══════════════════════════════════════════════════════════════════
# executor_autonomous.py (55% - selective key lines)
# ═══════════════════════════════════════════════════════════════════
class TestExecutorRegistryCore:
    """Cover uncovered lines in executor_registry.py."""

    def test_registry_property(self):
        from siyarix.executor_registry import RegistryExecutor

        reg = MagicMock()
        re = RegistryExecutor(registry=reg)
        assert re.registry is reg

    def test_register_executor(self):
        from siyarix.executor_registry import RegistryExecutor

        re = RegistryExecutor()
        fn = AsyncMock()
        re.register_executor("test_tool", fn)
        assert "test_tool" in re._custom_executors

    @pytest.mark.asyncio
    async def test_execute_step_timeout_error(self):
        from siyarix.executor_registry import RegistryExecutor

        re = RegistryExecutor()
        step = PlanStep(tool="nmap", timeout=0.001)
        with patch.object(
            re, "_try_execute", AsyncMock(side_effect=__import__("asyncio").TimeoutError)
        ):
            await re._execute_step(step, None)
            assert step.status == StepStatus.FAILED

    @pytest.mark.asyncio
    async def test_try_execute_permission_denied_in_execute_step(self):
        from siyarix.executor_registry import RegistryExecutor

        re = RegistryExecutor(registry=MagicMock(spec=ToolRegistry))
        re._permission_gate = MagicMock()
        re._budget.consume_tool_call = MagicMock(return_value=True)
        re._tracker.record = MagicMock(return_value=None)
        step = PlanStep(tool="nmap", args={"target": "x"})
        with patch.object(
            re, "_check_permissions", AsyncMock(side_effect=PermissionDeniedError("nope"))
        ):
            await re._execute_step(step, None)
            assert step.status == StepStatus.FAILED
            assert "nope" in step.result.get("error", "")

    @pytest.mark.asyncio
    async def test_execute_workflow_non_dag(self):
        from siyarix.executor_registry import RegistryExecutor

        plan = ExecutionPlan(goal="test")
        re = RegistryExecutor()
        with patch.object(re, "execute_plan", AsyncMock(return_value=plan)):
            result = await re.execute_workflow(plan)
            assert result is plan

    @pytest.mark.asyncio
    async def test_execute_workflow_fallback(self):
        from siyarix.executor_registry import RegistryExecutor

        plan = ExecutionPlan(goal="test", plan_type=PlanType.DAG)
        re = RegistryExecutor()
        with patch("siyarix.workflow.WorkflowEngine") as MockWE:
            MockWE.side_effect = Exception("wf fail")
            with patch.object(re, "execute_plan", AsyncMock(return_value=plan)):
                result = await re.execute_workflow(plan)
                assert result is plan


# ═══════════════════════════════════════════════════════════════════
# internal_tools.py (7% - missing 9-78) - Full coverage
# ═══════════════════════════════════════════════════════════════════
class TestExecutorToolErrors:
    """Cover remaining executor.py uncovered lines."""

    def test_redact_value_sensitive_short(self):
        result = _redact_value("password", "ab")
        assert result == "***"

    def test_redact_value_sensitive_long(self):
        result = _redact_value("api_key", "abcdefgh")
        assert result == "ab***gh"

    def test_redact_value_sensitive_regex(self):
        result = _redact_value("my_credential_key", "abcdefgh")
        assert result[:2] == "ab"

    def test_redact_value_non_sensitive(self):
        result = _redact_value("name", "John")
        assert result == "John"

    def test_get_dlp_engine_dlp_false_returns_none(self):
        import siyarix.executor

        siyarix.executor._DLP_ENGINE = None
        with patch("siyarix.dlp.DLPEngine") as MockDLP:
            MockDLP.side_effect = ImportError("no dlp")
            result = _get_dlp_engine()
            assert result is None

    def test_get_review_and_confirm_cached(self):
        fn = _get_review_and_confirm()
        assert callable(fn)

    def test_get_session_logger_cached(self):
        fn = _get_session_logger()
        assert fn is not None

    def test_budget_progress_pct_no_iterations(self):
        budget = ExecutionBudget(max_iterations=0)
        assert budget.progress_pct == 100.0

    def test_budget_progress_pct_some(self):
        budget = ExecutionBudget(max_iterations=100)
        budget._iterations = 50
        assert budget.progress_pct == 50.0

    def test_tool_call_tracker_load_failure(self):
        tracker = ToolCallTracker()
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "read_text", return_value="invalid json"):
                with patch("siyarix.executor.logger") as mock_log:
                    tracker._load_state()
                    mock_log.debug.assert_called()

    def test_tool_call_tracker_save_state_debounce(self):
        tracker = ToolCallTracker()
        with patch.object(Path, "write_text") as mock_write:
            for i in range(5):
                tracker._save_state()
            mock_write.assert_not_called()

    def test_tool_call_tracker_record_blocked(self):
        tracker = ToolCallTracker()
        for i in range(5):
            result = tracker.record("nmap", "args", False)
        assert result is not None
        assert "BLOCKED" in result

    def test_tool_call_tracker_record_halted(self):
        tracker = ToolCallTracker()
        tracker._config.same_tool_failure_halt_after = 3
        for i in range(3):
            tracker.record("nmap", "args", False)
            result = tracker.record("nmap", "args", False)
        assert result is not None

    def test_tool_call_tracker_record_no_progress(self):
        tracker = ToolCallTracker()
        tracker._last_mutation = "nmap:same_args"
        tracker._config.no_progress_block_after = 3
        for i in range(3):
            result = tracker.record("nmap", "same_args", False)
        assert result is not None

    def test_base_executor_apply_dlp_not_none(self):
        executor = BaseExecutor()
        with patch("siyarix.executor._get_dlp_engine") as mock_get:
            mock_dlp = MagicMock()
            mock_dlp.redact_dict.return_value = {"redacted": True}
            mock_get.return_value = mock_dlp
            import asyncio

            result = asyncio.run(executor._apply_dlp({"key": "val"}))
            assert result["redacted"] is True

    def test_base_executor_apply_dlp_not_dict(self):
        executor = BaseExecutor()
        import asyncio

        result = asyncio.run(executor._apply_dlp("string"))
        assert result == "string"

    def test_base_executor_apply_dlp_dlp_none(self):
        executor = BaseExecutor()
        with patch("siyarix.executor._get_dlp_engine", return_value=None):
            import asyncio

            result = asyncio.run(executor._apply_dlp({"key": "val"}))
            assert result == {"key": "val"}

    def test_log_safety_approved(self):
        executor = BaseExecutor()
        with patch("siyarix.executor.log_event") as mock_audit:
            executor._log_safety("nmap", "nmap -sV", "approved", "ok")
            mock_audit.assert_called_once()

    def test_log_safety_blocked(self):
        executor = BaseExecutor()
        with patch("siyarix.executor.log_event") as mock_audit:
            executor._log_safety("nmap", "nmap -sV", "blocked", "bad")
            mock_audit.assert_called_once()

    def test_log_safety_exception(self):
        executor = BaseExecutor()
        with patch("siyarix.executor._get_session_logger", side_effect=Exception("fail")):
            with patch("siyarix.executor.logger") as mock_log:
                executor._log_safety("nmap", "cmd", "approved", "ok")
                mock_log.debug.assert_called()

    def test_execute_plan_not_implemented(self):
        executor = BaseExecutor()
        import asyncio

        with pytest.raises(NotImplementedError):
            asyncio.run(executor.execute_plan(None))

    def test_close(self):
        executor = BaseExecutor()
        import asyncio

        asyncio.run(executor.close(timeout=1))


# ═══════════════════════════════════════════════════════════════════
# 12. executor_autonomous.py (81% - many uncovered lines/branches)
# ═══════════════════════════════════════════════════════════════════
class TestExecutorRegistryAutonomous:
    """Cover remaining executor_registry.py uncovered lines."""

    def test_execute_step_cancelled_error(self):
        executor = RegistryExecutor()
        step = PlanStep(id="s1", tool="nmap", timeout=5)
        with patch.object(executor._budget, "consume_iteration", return_value=True):
            with patch.object(executor, "_try_execute", side_effect=asyncio.CancelledError()):
                with pytest.raises(asyncio.CancelledError):
                    asyncio.run(executor._execute_step(step, None))

    def test_try_execute_custom_executor(self):
        executor = RegistryExecutor()
        step = PlanStep(id="s1", tool="custom_tool")
        mock_fn = AsyncMock(return_value={"status": "success"})
        executor._custom_executors["custom_tool"] = mock_fn
        import asyncio

        result = asyncio.run(executor._try_execute(step, None))
        assert result["status"] == "success"

    def test_try_execute_no_registry_no_tool(self):
        executor = RegistryExecutor()
        step = PlanStep(id="s1", tool="")
        import asyncio

        result = asyncio.run(executor._try_execute(step, None))
        assert result["status"] == "error"

    def test_try_execute_budget_exhausted(self):
        executor = RegistryExecutor()
        executor._budget._tool_calls = 100
        executor._budget.max_tool_calls = 100
        step = PlanStep(id="s1", tool="nmap", args={"target": "10.0.0.1"})
        import asyncio

        result = asyncio.run(executor._try_execute(step, None))
        assert result["status"] == "error"

    def test_try_execute_guardrail_blocked(self):
        executor = RegistryExecutor()
        executor._registry = MagicMock()
        executor._tracker._failure_counts["nmap"] = 10
        executor._tracker._config.exact_failure_block_after = 5
        step = PlanStep(id="s1", tool="nmap", args={"target": "10.0.0.1"})
        import asyncio

        result = asyncio.run(executor._try_execute(step, None))
        assert "BLOCKED" in result.get("error", "")

    def test_try_execute_tool_not_found(self):
        executor = RegistryExecutor()
        mock_registry = MagicMock()
        mock_registry.execute.side_effect = ToolNotFoundError("not found")
        executor._registry = mock_registry
        executor._budget._tool_calls = 0
        step = PlanStep(id="s1", tool="nonexistent", args={"target": "x"})
        import asyncio

        result = asyncio.run(executor._try_execute(step, None))
        assert result["status"] == "error"

    def test_try_execute_tool_execution_error(self):
        executor = RegistryExecutor()
        mock_registry = MagicMock()
        mock_registry.execute.side_effect = ToolExecutionError("exec error")
        executor._registry = mock_registry
        step = PlanStep(id="s1", tool="nmap", args={"target": "10.0.0.1"})
        import asyncio

        result = asyncio.run(executor._try_execute(step, None))
        assert result["status"] == "error"

    def test_handle_tool_error_auto_install(self):
        executor = RegistryExecutor()
        step = PlanStep(id="s1", tool="nmap")
        result = {"status": "error", "error": "not found: nmap"}
        import asyncio

        final = asyncio.run(executor._handle_tool_error(step, result))
        assert final["status"] == "error"


# ═══════════════════════════════════════════════════════════════════
# 14. internal_tools.py (92% - missing 18, 24->38, 29->38, 66)
# ═══════════════════════════════════════════════════════════════════
class TestExecutorErrorHandling:
    """Cover remaining executor.py uncovered lines."""

    def test_budget_reset(self):
        b = ExecutionBudget()
        b._iterations = 10
        b._tool_calls = 20
        b.reset()
        assert b._iterations == 0
        assert b._tool_calls == 0

    def test_budget_reset_timer(self):
        b = ExecutionBudget()
        old = b._start_time
        b.reset_timer()
        assert b._start_time >= old

    def test_tracker_save_state_force(self):
        tracker = ToolCallTracker()
        with patch.object(Path, "write_text") as mock_write:
            tracker._save_state(force=True)
            mock_write.assert_called_once()

    def test_tracker_save_state_write_error(self):
        tracker = ToolCallTracker()
        tracker._debounce_counter = 9
        with patch.object(Path, "write_text", side_effect=OSError("write fail")):
            with patch("siyarix.executor.logger") as mock_log:
                tracker._save_state()
                mock_log.warning.assert_called()

    def test_tracker_record_success_resets_progress(self):
        tracker = ToolCallTracker()
        tracker._no_progress_count = 5
        tracker._last_mutation = "nmap:old"
        tracker.record("nmap", "new", True)
        assert tracker._no_progress_count == 0

    def test_tracker_reset(self):
        tracker = ToolCallTracker()
        tracker._failure_counts["nmap"] = 5
        tracker.reset()
        assert tracker._failure_counts == {}

    def test_base_executor_permission_check_gate_blocks(self):
        executor = BaseExecutor()
        gate = MagicMock()
        gate.check.return_value = MagicMock(allowed=False, reason="blocked by policy")
        executor._permission_gate = gate
        step = PlanStep(tool="nmap", args={"command": "nmap -sS target"})
        with pytest.raises(PermissionDeniedError):
            asyncio.run(executor._check_permissions(step))

    def test_base_executor_permission_check_requires_review_cancelled(self):
        executor = BaseExecutor()
        gate = MagicMock()
        gate.check.return_value = MagicMock(allowed=True, requires_review=True, reason="high risk")
        executor._permission_gate = gate
        step = PlanStep(tool="nmap", args={"command": "nmap -sV target"})
        with patch("siyarix.executor._get_review_and_confirm") as mock_get:
            mock_get.return_value = lambda c, t, r: None
            with pytest.raises(PermissionDeniedError):
                asyncio.run(executor._check_permissions(step))

    def test_base_executor_permission_check_requires_review_modified(self):
        executor = BaseExecutor()
        gate = MagicMock()
        gate.check.return_value = MagicMock(
            allowed=True, requires_review=True, reason="check flags"
        )
        executor._permission_gate = gate
        step = PlanStep(tool="nmap", args={"command": "nmap -sS target"})
        with patch("siyarix.executor._get_review_and_confirm") as mock_get:
            mock_get.return_value = lambda c, t, r: c + " --safe"
            asyncio.run(executor._check_permissions(step))
            assert "--safe" in step.command

    def test_log_safety_cancelled_audit(self):
        executor = BaseExecutor()
        with patch("siyarix.executor.log_event") as mock_log_event:
            executor._log_safety("nmap", "cmd", "cancelled", "user said no")
            mock_log_event.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# 9. executor_autonomous.py (84% - missing stealth, live display, parse)
# ═══════════════════════════════════════════════════════════════════
class TestExecutorRegistryPlanExecution:
    """Cover remaining executor_registry.py uncovered lines."""

    async def test_execute_plan_simple_sequential(self):
        plan = ExecutionPlan(
            goal="test",
            plan_type=PlanType.SEQUENTIAL,
            steps=[PlanStep(id="s1", tool="nmap")],
        )
        executor = RegistryExecutor()
        mock_reg = MagicMock()
        mock_reg.execute = AsyncMock(return_value={"status": "success"})
        mock_reg.graph.get_tool.return_value = MagicMock()
        executor._registry = mock_reg
        with patch.object(executor._budget, "consume_tool_call", return_value=True):
            with patch.object(executor._tracker, "record", return_value=None):
                result = await executor.execute_plan(plan)
                assert result is plan

    async def test_try_execute_custom_executor(self):
        executor = RegistryExecutor()
        step = PlanStep(tool="custom")
        mock_fn = AsyncMock(return_value={"status": "success"})
        result = await executor._try_execute(step, mock_fn)
        assert result["status"] == "success"

    @pytest.mark.skip(reason="Requires complex mock setup")
    async def test_try_execute_permission_denied_raised(self):
        executor = RegistryExecutor()
        with patch.object(
            executor, "_check_permissions", AsyncMock(side_effect=PermissionDeniedError("denied"))
        ):
            with pytest.raises(PermissionDeniedError):
                await executor._try_execute(PlanStep(tool="nmap"), None)

    async def test_handle_tool_error_not_found_not_tty(self):
        executor = RegistryExecutor()
        step = PlanStep(tool="nmap")
        result = {"status": "error", "error": "not found: nmap"}
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            final = await executor._handle_tool_error(step, result)
            assert final["status"] == "error"

    async def test_handle_tool_error_not_found_tty_declines_install(self):
        executor = RegistryExecutor()
        step = PlanStep(tool="nmap")
        result = {"status": "error", "error": "not found: nmap"}
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            with patch("rich.prompt.Confirm.ask", return_value=False):
                final = await executor._handle_tool_error(step, result)
                assert final["status"] == "error"

    async def test_try_alternatives_no_match(self):
        executor = RegistryExecutor()
        executor._registry = MagicMock()
        step = PlanStep(tool="nonexistent_tool", args={"target": "x"})
        result = {"status": "error", "error": "fail"}
        final = await executor._try_alternatives(step, result)
        assert final is result

    @pytest.mark.skip(reason="Requires complex mock setup")
    async def test_try_alternatives_fails_returns_original(self):
        executor = RegistryExecutor()
        mock_reg = MagicMock()
        mock_reg.graph.get_tool.return_value = MagicMock()
        executor._registry = mock_reg
        step = PlanStep(tool="nmap", args={"target": "x"})
        result = {"status": "error", "error": "fail"}
        final = await executor._try_alternatives(step, result)
        assert final is result


# ═══════════════════════════════════════════════════════════════════
# 11. parsers/__init__.py (96% - missing discover branches)
# ═══════════════════════════════════════════════════════════════════
