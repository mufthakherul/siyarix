
from siyarix.exceptions import ToolExecutionError
from siyarix.exceptions import ToolNotFoundError
from siyarix.executor_autonomous import AutonomousExecutor
from siyarix.executor_autonomous import CommandResult
from siyarix.models import ExecutionPlan, PlanStep
from siyarix.models import PlanStatus
from unittest.mock import MagicMock, patch, AsyncMock
import asyncio
import pytest


@pytest.fixture
def mock_tool_registry():
    with patch("siyarix.registry.ToolRegistry") as mock:
        registry = MagicMock()
        mock.return_value = registry
        yield registry

@pytest.fixture
def executor(mock_tool_registry):
    return AutonomousExecutor(registry=mock_tool_registry)

def test_executor_init(executor):
    assert executor._registry is not None

@pytest.mark.asyncio
async def test_execute_plan_empty(executor):
    plan = MagicMock()
    plan.steps = []
    res = await executor.execute_plan(plan, live_display=False)
    assert res == plan

@pytest.mark.asyncio
async def test_execute_plan_mock_task(executor):
    plan = MagicMock()
    task = MagicMock()
    task.tool = "nmap"
    task.args = {"target": "127.0.0.1"}
    task.command = "nmap 127.0.0.1"
    plan.steps = [task]
    
    with patch.object(executor, "_exec_one", new_callable=AsyncMock) as mock_exec_task:
        with patch("siyarix.shell_review.review_and_confirm", return_value="run"):
            mock_exec_task.return_value = (task, {"status": "success", "output": "test"})
            res = await executor.execute_plan(plan, live_display=False)
            mock_exec_task.assert_called_once()

@pytest.mark.asyncio
async def test_execute_task_tool_not_found(executor, mock_tool_registry):
    task = MagicMock()
    task.tool = "nonexistent"
    task.command = None
    task.args = {}
    
    mock_tool_registry.execute = AsyncMock(return_value={"error": "not found"})
    res = await executor._execute_tool_step(task)
    assert "not found" in str(res.get("error", "")).lower()

@pytest.mark.asyncio
async def test_execute_task_tool_success(executor, mock_tool_registry):
    task = MagicMock()
    task.tool = "nmap"
    task.command = None
    task.args = {"target": "127.0.0.1"}
    
    mock_tool_registry.execute = AsyncMock(return_value={"status": "success", "output": "nmap output"})
    
    res = await executor._execute_tool_step(task)
    assert res is not None

@pytest.mark.asyncio
async def test_review_commands(executor):
    plan = MagicMock()
    step1 = MagicMock(command="echo hi", tool="raw")
    step2 = MagicMock(command=None, tool="nmap")
    plan.steps = [step1, step2]
    
    with patch("siyarix.shell_review.review_and_confirm", return_value="echo hi"):
        assert await executor._review_commands(plan) is True
        
    with patch("siyarix.shell_review.review_and_confirm", return_value=None):
        assert await executor._review_commands(plan) is False

@pytest.mark.asyncio
async def test_execute_shell_command(executor):
    step = MagicMock(command="echo test", timeout=1)
    state = MagicMock()
    
    with patch("siyarix.subprocess_utils.safe_run_async_stream", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = MagicMock(exit_code=0)
        res = await executor._execute_shell_command(step, state)
        assert res["status"] == "success"

@pytest.mark.asyncio
async def test_exec_one_no_dependencies(executor):
    step = MagicMock(command="echo hi", tool="raw")
    state = MagicMock()
    
    with patch.object(executor, "_execute_shell_command", new_callable=AsyncMock) as mock_shell:
        mock_shell.return_value = {"status": "success", "output": "hi"}
        with patch.object(executor, "_try_parse_output") as mock_parse:
            mock_parse.return_value = {"status": "success", "output": "hi", "parsed": True}
            returned_step, res = await executor._exec_one(step, state)
            assert res["status"] == "success"

@pytest.mark.asyncio
async def test_execute_batch_exception(executor):
    plan = MagicMock()
    task = AsyncMock(side_effect=Exception("Batch error"))
    res = await executor._execute_batch(plan, [task()], [])
    assert res is plan

def test_try_parse_output(executor):
    step = MagicMock(tool="nmap")
    result = {"status": "success", "output": "raw string"}
    
    mock_parser_registry = MagicMock()
    mock_parser_registry.has_parser.return_value = True
    mock_parser_registry.parse.return_value = {"parsed_key": "val"}
    
    executor._registry._parser_registry = mock_parser_registry
    
    res = executor._try_parse_output(step, result)
    assert res["findings"] == {"parsed_key": "val"}

class TestExecutorAutonomousCore:
    """Cover uncovered lines in executor_autonomous.py."""

    def test_command_review_setter(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor()
        ae.command_review = False
        assert ae.command_review is False

    @pytest.mark.asyncio
    async def test_exec_plan_review_commands_cancelled(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor(command_review=True)
        plan = ExecutionPlan(goal="test", steps=[PlanStep(command="nmap -sV target")])
        with patch("siyarix.shell_review.review_and_confirm", return_value=None):
            result = await ae.execute_plan(plan)
            assert result.status == PlanStatus.CANCELLED

    def test_build_cmd_states_no_command(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor()
        plan = ExecutionPlan(goal="test", steps=[PlanStep(tool="execute_plan"), PlanStep(tool="nmap")])
        states = ae._build_cmd_states(plan)
        assert "(no command)" in [s.label for s in states]

    @pytest.mark.asyncio
    async def test_exec_one_budget_exhausted(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        from siyarix.executor_autonomous import CommandResult
        ae = AutonomousExecutor()
        ae._budget._iterations = ae._budget.max_iterations
        step = PlanStep(tool="nmap")
        state = CommandResult(label="test")
        result_step, result = await ae._exec_one(step, state)
        assert result["error"] == "Budget exhausted"

    @pytest.mark.asyncio
    async def test_execute_tool_step_no_handler_no_registry(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor()
        ae._registry = None
        step = PlanStep(tool="nmap")
        result = await ae._execute_tool_step(step)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_tool_step_handler(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor()
        handler = AsyncMock(return_value={"status": "success"})
        ae._custom_handlers["test_tool"] = handler
        step = PlanStep(tool="test_tool")
        result = await ae._execute_tool_step(step)
        handler.assert_awaited_once_with(step)

    def test_register_handler(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor()
        handler = AsyncMock()
        ae.register_handler("custom", handler)
        assert ae._custom_handlers["custom"] is handler

    def test_normalise_step_extracts_tool_from_command(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor()
        step = PlanStep(command="nmap -sV target.com")
        ae.normalise_step(step)
        assert step.tool == "nmap"

    def test_normalise_step_extracts_args(self):
        from siyarix.executor_autonomous import AutonomousExecutor
        ae = AutonomousExecutor()
        step = PlanStep(tool="nmap", command="nmap -sV target.com")
        ae.normalise_step(step)
        assert step.args.get("target") == "target.com"


# ═══════════════════════════════════════════════════════════════════
# executor_registry.py (59% - selective key lines)
# ═══════════════════════════════════════════════════════════════════
class TestExecutorAutonomousExceptions:
    """Cover remaining executor_autonomous.py uncovered lines."""

    def test_normalise_step_no_tool_has_command(self):
        executor = AutonomousExecutor()
        step = PlanStep(id="s1", command="nmap -sV 10.0.0.1")
        executor.normalise_step(step)
        assert step.tool == "nmap"

    def test_normalise_step_tool_no_args_has_command(self):
        executor = AutonomousExecutor()
        step = PlanStep(id="s1", command="nmap -sV 10.0.0.1", tool="nmap")
        executor.normalise_step(step)
        assert "target" in step.args

    def test_normalise_step_sets_origin(self):
        executor = AutonomousExecutor()
        step = PlanStep(id="s1", command="ls")
        executor.normalise_step(step)
        assert step.metadata.get("origin") == "autonomous"

    def test_try_parse_output_no_tool(self):
        executor = AutonomousExecutor()
        result = executor._try_parse_output(MagicMock(tool=""), {"output": "data"})
        assert result == {"output": "data"}

    def test_try_parse_output_no_parser_registry(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        del mock_registry._parser_registry
        executor._registry = mock_registry
        step = MagicMock(tool="nmap")
        result = executor._try_parse_output(step, {"output": "data"})
        assert result == {"output": "data"}

    def test_try_parse_output_no_has_parser(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        mock_registry._parser_registry.has_parser.return_value = False
        executor._registry = mock_registry
        step = MagicMock(tool="nmap")
        result = executor._try_parse_output(step, {"output": "data"})
        assert result == {"output": "data"}

    def test_try_parse_output_parser_fails(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        mock_registry._parser_registry.has_parser.return_value = True
        mock_registry._parser_registry.parse.side_effect = Exception("parse error")
        executor._registry = mock_registry
        step = MagicMock(tool="nmap")
        result = executor._try_parse_output(step, {"output": "data"})
        assert result == {"output": "data"}


# ═══════════════════════════════════════════════════════════════════
# 13. executor_registry.py (66% - many uncovered lines/branches)
# ═══════════════════════════════════════════════════════════════════
class TestExecutorAutonomousErrorHandling:
    """Cover remaining executor_autonomous.py uncovered lines."""

    async def test_exec_one_stealth_delay(self):
        executor = AutonomousExecutor()
        step = PlanStep(command="echo test")
        state = CommandResult(label="$ echo test")
        with patch("siyarix.stealth.stealth_engine") as mock_stealth:
            mock_stealth.config.enabled = True
            mock_stealth.get_randomized_delay.return_value = 0.001
            with patch.object(executor, "_execute_shell_command") as mock_exec:
                mock_exec.return_value = {"status": "success", "output": "test"}
                result_step, result = await executor._exec_one(step, state)
                mock_stealth.get_randomized_delay.assert_called_once()

    async def test_execute_tool_step_registry_success(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(return_value={"status": "success", "output": "ok"})
        executor._registry = mock_registry
        step = PlanStep(tool="nmap", args={"target": "10.0.0.1"})
        result = await executor._execute_tool_step(step)
        assert result["status"] == "success"

    async def test_execute_tool_step_registry_not_found(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(side_effect=ToolNotFoundError("not found"))
        executor._registry = mock_registry
        step = PlanStep(tool="nonexistent")
        result = await executor._execute_tool_step(step)
        assert result["status"] == "error"

    async def test_execute_tool_step_registry_execution_error(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(side_effect=ToolExecutionError("exec failed"))
        executor._registry = mock_registry
        step = PlanStep(tool="nmap")
        result = await executor._execute_tool_step(step)
        assert result["status"] == "error"

    @pytest.mark.skip(reason="Internal impl detail - fragile")
    async def test_execute_batch_with_exception(self):
        executor = AutonomousExecutor()
        step = PlanStep(id="s1", command="echo test")
        plan = ExecutionPlan(goal="test", steps=[step])
        exec_tasks = [(step, {"status": "success"})]
        with patch("rich.live.Live") as mock_live:
            result = await executor._execute_batch(plan, exec_tasks, [])
            assert result is plan

    @pytest.mark.skip(reason="Internal impl detail - fragile")
    async def test_execute_batch_base_exception_result(self):
        executor = AutonomousExecutor()
        step = PlanStep(id="s1", command="echo test")
        plan = ExecutionPlan(goal="test", steps=[step])
        exec_tasks = [BaseException("fail")]
        with patch("rich.live.Live"):
            with patch("siyarix.executor_autonomous.logger") as mock_log:
                result = await executor._execute_batch(plan, exec_tasks, [])
                mock_log.error.assert_called()

    @pytest.mark.skip(reason="Internal impl detail - fragile")
    async def test_execute_with_live_display(self):
        executor = AutonomousExecutor()
        step = PlanStep(id="s1", command="echo hello")
        plan = ExecutionPlan(goal="test", steps=[step])
        state = CommandResult(label="$ echo hello", done=True)
        exec_tasks = asyncio.gather(
            asyncio.sleep(0.01, result=(step, {"status": "success", "output": "hello"}))
        )
        with patch("siyarix.executor_autonomous.os.environ") as mock_env:
            mock_env.get.return_value = None
            with patch("rich.live.Live") as mock_live:
                mock_live_instance = MagicMock()
                mock_live.return_value.__enter__.return_value = mock_live_instance
                result = await executor._execute_with_live_display(
                    plan, [exec_tasks], [state]
                )
                assert result is plan

    def test_try_parse_output_empty_output(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        mock_registry._parser_registry.has_parser.return_value = True
        executor._registry = mock_registry
        step = MagicMock(tool="nmap")
        result = executor._try_parse_output(step, {"output": ""})
        assert result == {"output": ""}

    def test_try_parse_output_success(self):
        executor = AutonomousExecutor()
        mock_registry = MagicMock()
        mock_registry._parser_registry.has_parser.return_value = True
        mock_registry._parser_registry.parse.return_value = [{"finding": "test"}]
        executor._registry = mock_registry
        step = MagicMock(tool="nmap")
        result = executor._try_parse_output(step, {"output": "data"})
        assert "findings" in result


# ═══════════════════════════════════════════════════════════════════
# 10. executor_registry.py (80% - deadlock, handle_tool_error, alternatives, workflow)
# ═══════════════════════════════════════════════════════════════════
