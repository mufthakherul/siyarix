# SPDX-License-Identifier: AGPL-3.0-or-later

"""End-to-End (E2E) and Live Testing Suite for Siyarix Agentic Engine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from typer.main import get_command

from siyarix.cli import app
from siyarix.planner import (
    ExecutionPlan,
    PlanStep,
    Planner,
    StepResult,
    StepStatus,
)
from siyarix.tool_installer import ToolInstaller


def test_cli_scan_dry_run() -> None:
    """E2E Test 1: Verify direct CLI 'scan' execution with --dry-run."""
    runner = CliRunner()
    command = get_command(app)

    result = runner.invoke(
        command, ["scan", "127.0.0.1", "--mode", "registry", "--dry-run", "--no-banner"]
    )

    assert result.exit_code == 0
    assert (
        "dry run" in result.output.lower()
        or "plan" in result.output.lower()
        or "target" in result.output.lower()
    )


def test_cli_run_conditional_workflow() -> None:
    """E2E Test 2: Verify direct CLI 'run' with a conditional natural language workflow."""
    runner = CliRunner()
    command = get_command(app)

    result = runner.invoke(
        command,
        [
            "run",
            "if port_80_open then scan 127.0.0.1 with nikto else scan 127.0.0.1 with nmap",
            "--mode",
            "registry",
            "--dry-run",
            "--no-banner",
        ],
    )

    assert result.exit_code == 0


def test_tool_installation_success() -> None:
    """E2E Test 3: Validate tool installation succeeds when package manager works."""
    installer = ToolInstaller()

    with (
        patch.object(installer, "_detect_package_manager", return_value="apt-get"),
        patch("siyarix.tool_installer.shutil.which", return_value=None),
        patch("siyarix.tool_installer.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout="installed", stderr="")
        result = installer.install("gobuster")
        assert result.success is True


def test_tool_installation_failure() -> None:
    """E2E Test 3b: Validate tool installation fails gracefully."""
    installer = ToolInstaller()

    with (
        patch.object(installer, "_detect_package_manager", return_value="apt-get"),
        patch("siyarix.tool_installer.shutil.which", return_value=None),
        patch("siyarix.tool_installer.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        result = installer.install("nonexistent_tool_xyz")
        assert result.success is False


@pytest.mark.asyncio
async def test_live_tool_fallback_recovery() -> None:
    """E2E Test 4: Validate plan adaptation under failure states."""
    planner = Planner()

    plan = ExecutionPlan(
        goal="scan 10.0.0.1",
        raw_instruction="scan 10.0.0.1",
        steps=[
            PlanStep(id="step_nmap", tool="nmap", args={"target": "10.0.0.1"}),
        ],
    )

    failed_step = plan.steps[0]
    failed_step.status = StepStatus.FAILED
    failed_step.result = {"error": "Host seems down. If it is really up, try -Pn"}

    adapted = planner.adapt_plan(plan, failed_step, "Host seems down. If it is really up, try -Pn")

    has_pn_retry = any("-Pn" in str(s.args) for s in adapted.steps if s.id != "step_nmap")
    assert has_pn_retry or adapted.steps[0].retry_count > 0
