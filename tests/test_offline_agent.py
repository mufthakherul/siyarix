from unittest.mock import AsyncMock, MagicMock

import pytest

from phalanx.core.agentic_loop import AgenticLoop
from phalanx.engine import (ExecutionEngine, ExecutionStep, StepResult,
                            StepStatus)
from phalanx.interpreter import RuleInterpreter, TaskCategory
from phalanx.knowledge_graph import KnowledgeGraph
from phalanx.planner import StepType, TaskPlanner


@pytest.mark.asyncio
async def test_pillar_1_conditional_interpreter_and_evaluator():
    # Test Pillar 1: Logical chains and negation evaluations
    interpreter = RuleInterpreter()

    # Check conditional parsing
    task_cond = interpreter.interpret(
        "if port_80_open then scan 192.168.1.1 with nikto else scan 192.168.1.1 with nmap"
    )
    assert task_cond.category == TaskCategory.WORKFLOW
    assert task_cond.action == "conditional"
    assert task_cond.flags["condition"] == "port_80_open"
    assert len(task_cond.sub_tasks) == 2
    assert task_cond.sub_tasks[0].flags["branch"] == "then"
    assert task_cond.sub_tasks[1].flags["branch"] == "else"

    # Check logical chain parsing
    task_chain = interpreter.interpret(
        "scan 192.168.1.1 with nmap && scan 192.168.1.1 with nikto"
    )
    assert task_chain.category == TaskCategory.WORKFLOW
    assert task_chain.action == "chain"
    assert len(task_chain.sub_tasks) == 2
    assert task_chain.sub_tasks[1].flags.get("chain_op") == "&&"


@pytest.mark.asyncio
async def test_pillar_2_knowledge_graph_and_reflection():
    # Test Pillar 2: Live graph ingestion and traverse-driven reflection
    engine = MagicMock()
    graph = KnowledgeGraph()
    engine.graph = graph

    # Ingest mock findings
    graph.ingest_finding({"host": "10.0.0.5", "port": 22, "service": "ssh"})
    graph.ingest_finding({"host": "10.0.0.5", "port": 80, "service": "http"})

    # Run tactical reflection
    loop = AgenticLoop(engine=engine, goal="Bruteforce active nodes", target="10.0.0.5")
    loop._reflect()

    # Assert queued reflective tactical follow-ups
    assert any("hydra brute force" in q for q in loop._reflection_queue)
    assert any("nuclei vulnerability scan" in q for q in loop._reflection_queue)
    assert any("gobuster directory scan" in q for q in loop._reflection_queue)


@pytest.mark.asyncio
async def test_pillar_3_adaptive_plan_mutator():
    # Test Pillar 3: Dynamic Plan Mutator fallback and error recovery
    engine = ExecutionEngine()

    # 1. Nmap Ping Bypass Mutator Check
    step_nmap = ExecutionStep(
        id="step_1",
        step_type=StepType.TOOL_RUN,
        tool="nmap",
        args=[],
        target="192.168.1.100",
    )
    sr_failed = StepResult(
        step_id="step_1",
        status=StepStatus.FAILED,
        error="Host seems down. If it is really up, try -Pn",
    )
    still_pending = []

    engine._adapt_plan_on_step_result(step_nmap, sr_failed, MagicMock(), still_pending)
    assert len(still_pending) == 1
    assert still_pending[0].tool == "nmap"
    assert "-Pn" in still_pending[0].args
    assert still_pending[0].id == "step_1_retry_pn"

    # 2. Gobuster Zero-findings Fallback Mutator Check
    step_gobuster = ExecutionStep(
        id="step_2",
        step_type=StepType.TOOL_RUN,
        tool="gobuster",
        args=[],
        target="192.168.1.100",
    )
    sr_zero = StepResult(step_id="step_2", status=StepStatus.SUCCESS, findings=[])
    still_pending_gobuster = []

    engine._adapt_plan_on_step_result(
        step_gobuster, sr_zero, MagicMock(), still_pending_gobuster
    )
    assert len(still_pending_gobuster) == 1
    assert still_pending_gobuster[0].tool == "nikto"
    assert still_pending_gobuster[0].id == "step_2_fallback_nikto"

    # 3. Shell Permission Error Mutator Check
    step_shell = ExecutionStep(
        id="step_3", step_type=StepType.SHELL_CMD, command="cat /etc/shadow"
    )
    sr_permission = StepResult(
        step_id="step_3", status=StepStatus.FAILED, error="Permission denied"
    )
    still_pending_shell = []

    engine._adapt_plan_on_step_result(
        step_shell, sr_permission, MagicMock(), still_pending_shell
    )
    assert len(still_pending_shell) == 1
    assert (
        "sudo" in still_pending_shell[0].command
        or "whoami" in still_pending_shell[0].command
    )


@pytest.mark.asyncio
async def test_pillar_4_shell_compiler_matching():
    # Test Pillar 4: Interpreter matches abstract intents, planner compiles to platform-specific command
    interpreter = RuleInterpreter()
    planner = TaskPlanner()

    # Interpret custom abstract command
    task = interpreter.interpret("show connections")
    assert task.category == TaskCategory.CUSTOM
    assert task.action == "network_connections"
    assert task.flags["intent"] == "network_connections"

    # Planner compile check
    plan = await planner.plan("show connections")
    assert len(plan.steps) == 1
    assert plan.steps[0].step_type == StepType.SHELL_CMD
    assert plan.steps[0].command is not None


@pytest.mark.asyncio
async def test_tool_auto_installation():
    # Test auto-installation mechanism
    from unittest.mock import patch

    engine = ExecutionEngine()

    def mock_which(cmd):
        if cmd == "nmap":
            return None
        return f"/mocked/bin/{cmd}"

    with (
        patch("shutil.which", side_effect=mock_which),
        patch(
            "phalanx.output.output.prompt_confirm", return_value=True
        ) as mock_confirm,
        patch("phalanx.engine.run_tool_complete", new_callable=AsyncMock) as mock_run,
    ):
        mock_run.return_value.exit_code = 0
        mock_run.return_value.stdout = "Successfully installed"
        mock_run.return_value.stderr = ""

        success = await engine._try_install_tool("nmap")

        assert success is True
        mock_confirm.assert_called_once()
        mock_run.assert_called()
