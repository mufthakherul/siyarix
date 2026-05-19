"""End-to-End (E2E) and Live Testing Suite for Phalanx Agentic Engine.

This test suite validates full execution pipelines under mock environments:
1. CLI scans: Target validation, parsing, planning.
2. Conditional natural language workflows: Chained conditionals parsing and scheduling.
3. Interactive user confirmation prompts: Confirmed vs declined package auto-installation.
4. Live-like execution fallbacks: Mutators and self-correction loops under failure states.
"""

from __future__ import annotations

import sys
import shutil
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from click.testing import CliRunner
from typer.main import get_command

from phalanx.main import app
from phalanx.engine import ExecutionEngine, StepResult, StepStatus, ExecutionStep, EngineResult, ExecutionMode
from phalanx.planner import TaskPlanner, StepType, ExecutionPlan
from phalanx.interpreter import RuleInterpreter, TaskCategory
from phalanx.knowledge_graph import KnowledgeGraph, NodeType
from phalanx.output import output
from phalanx.audit_log import audit, AuditEventType


def test_cli_scan_dry_run() -> None:
    """E2E Test 1: Verify direct CLI 'scan' execution with --dry-run."""
    runner = CliRunner()
    command = get_command(app)

    # Invoke dry-run scan on a valid local loopback IP
    result = runner.invoke(
        command,
        ["scan", "127.0.0.1", "--mode", "registry", "--dry-run", "--no-banner"]
    )

    assert result.exit_code == 0
    # Output should print the offline execution plan or steps
    assert "plan" in result.output.lower() or "target" in result.output.lower()


def test_cli_run_conditional_workflow() -> None:
    """E2E Test 2: Verify direct CLI 'run' with a conditional natural language workflow."""
    runner = CliRunner()
    command = get_command(app)

    # Invoke dry-run with conditional instruction
    result = runner.invoke(
        command,
        [
            "run",
            "if port_80_open then scan 127.0.0.1 with nikto else scan 127.0.0.1 with nmap",
            "--mode",
            "registry",
            "--dry-run",
            "--no-banner"
        ]
    )

    assert result.exit_code == 0
    # Output should include references to nikto and nmap branches
    assert "nikto" in result.output.lower()
    assert "nmap" in result.output.lower()


@pytest.mark.asyncio
async def test_interactive_installation_confirm() -> None:
    """E2E Test 3: Validate interactive prompt confirmations during missing tool auto-installations."""
    engine = ExecutionEngine()

    def mock_which_installer(cmd):
        # Pretend the required tool is missing but winget installer is available on PATH
        if cmd == "gobuster":
            return None
        if cmd == "winget":
            return "/usr/bin/winget"
        return None

    # Test Scenario A: User confirms the auto-installation prompt
    with patch("shutil.which", side_effect=mock_which_installer), \
         patch("phalanx.output.output.prompt_confirm", return_value=True) as mock_confirm, \
         patch("phalanx.engine.run_tool_complete", new_callable=AsyncMock) as mock_run:

        mock_run.return_value.exit_code = 0
        mock_run.return_value.stdout = "Successfully installed gobuster via winget"
        mock_run.return_value.stderr = ""

        success = await engine._try_install_tool("gobuster")

        assert success is True
        mock_confirm.assert_called_once()
        mock_run.assert_called()

    # Test Scenario B: User declines the auto-installation prompt
    with patch("shutil.which", side_effect=mock_which_installer), \
         patch("phalanx.output.output.prompt_confirm", return_value=False) as mock_confirm, \
         patch("phalanx.engine.run_tool_complete", new_callable=AsyncMock) as mock_run:

        success = await engine._try_install_tool("gobuster")

        assert success is False
        mock_confirm.assert_called_once()
        mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_live_tool_fallback_recovery() -> None:
    """E2E Test 4: Validate live-like execution self-correction and mutator pivoting."""
    engine = ExecutionEngine(mode=ExecutionMode.INTEGRATED)
    engine._graph = KnowledgeGraph()

    # Define a target step that fails due to host detection / ping block
    step_nmap = ExecutionStep(
        id="step_nmap_ping",
        step_type=StepType.TOOL_RUN,
        tool="nmap",
        args=["10.0.0.1"],
        target="10.0.0.1"
    )
    
    sr_failed = StepResult(
        step_id="step_nmap_ping",
        status=StepStatus.FAILED,
        error="Host seems down. If it is really up, try -Pn"
    )

    pending_steps = []

    # Inject the failure into the live plan mutator
    engine._adapt_plan_on_step_result(step_nmap, sr_failed, MagicMock(), pending_steps)

    # Check that the mutator automatically corrected and scheduled a ping bypass scan
    assert len(pending_steps) == 1
    assert pending_steps[0].tool == "nmap"
    assert "-Pn" in pending_steps[0].args
    assert pending_steps[0].id == "step_nmap_ping_retry_pn"

    # Define a second step that yields zero findings (directory fuzzing)
    step_gobuster = ExecutionStep(
        id="step_gobuster_fuzz",
        step_type=StepType.TOOL_RUN,
        tool="gobuster",
        args=["-u", "http://10.0.0.1"],
        target="10.0.0.1"
    )

    sr_zero = StepResult(
        step_id="step_gobuster_fuzz",
        status=StepStatus.SUCCESS,
        findings=[]
    )

    pending_steps_fuzz = []
    engine._adapt_plan_on_step_result(step_gobuster, sr_zero, MagicMock(), pending_steps_fuzz)

    # Verify fallback to Nikto web scanner was triggered
    assert len(pending_steps_fuzz) == 1
    assert pending_steps_fuzz[0].tool == "nikto"
    assert pending_steps_fuzz[0].id == "step_gobuster_fuzz_fallback_nikto"
