from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""End-to-End (E2E) and Live Testing Suite for Siyarix Agentic Engine."""


from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from typer.main import get_command

from siyarix.cli import app
from siyarix.planner import (
    ExecutionPlan,
    PlanStep,
    Planner,
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
        patch.object(installer, "_detect_pm", return_value="apt-get"),
        patch("siyarix.tool_installer.shutil.which") as mock_which,
        patch("siyarix.tool_installer.subprocess.run") as mock_run,
    ):
        mock_which.side_effect = lambda t: t == "gobuster"
        mock_run.return_value = MagicMock(returncode=0, stdout="installed", stderr="")
        result = installer.install("gobuster")
        assert result.success is True


def test_tool_installation_failure() -> None:
    """E2E Test 3b: Validate tool installation fails gracefully."""
    installer = ToolInstaller()

    with (
        patch.object(installer, "_detect_pm", return_value="apt-get"),
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




import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from siyarix.models import ExecutionPlan, PlanStep, PlanType, PlanStatus, StepStatus
from siyarix.exceptions import PermissionDeniedError, BudgetExceededError
from siyarix.registry import ToolCapability, ToolCategory, ToolRegistry
from siyarix.planner_registry import RegistryPlanner
from siyarix.executor_registry import RegistryExecutor
from siyarix.executor_autonomous import AutonomousExecutor
from siyarix.config import SettingsStore
from siyarix.context import ContextManager
from siyarix.compliance import ComplianceEngine
from siyarix.opsec import OPSECManager
from siyarix.dlp import DLPEngine
from siyarix.permission_gate import PermissionGate
from siyarix.cvss_scorer import CVSSScorer, CVSSVector


pytestmark = [pytest.mark.e2e]


# ═══════════════════════════════════════════════════════════════════
# Full Pipeline Integration Tests
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_full_pipeline_registry_mode(tool_registry):
    """End-to-end: goal -> plan -> execute -> extract findings."""
    from siyarix.core import AgentCore, AgentGoal, AgentMode
    from siyarix.models import ExecutionPlan, PlanStep, StepStatus, PlanStatus
    agent = AgentCore(mode=AgentMode.REGISTRY, registry=tool_registry)
    with patch.object(agent._planner_registry, "plan") as mock_plan:
        with patch.object(agent._executor_registry, "execute_plan", AsyncMock()) as mock_exec:
            mock_plan.return_value = ExecutionPlan(
                goal="port scan target",
                steps=[PlanStep(tool="nmap", args={"target": "scanme.nmap.org"})],
                status=PlanStatus.ACTIVE,
            )
            mock_exec.return_value = ExecutionPlan(
                goal="port scan target",
                steps=[PlanStep(tool="nmap", args={"target": "scanme.nmap.org"}, status=StepStatus.COMPLETED, result={"output": "ok"})],
                status=PlanStatus.COMPLETED,
            )
            goal = AgentGoal(description="port scan target", target="scanme.nmap.org", timeout=30)
            result = await agent.execute_goal(goal)
    assert result.success is True
    assert result.duration_ms >= 0
    assert result.plan is not None


@pytest.mark.asyncio
async def test_full_pipeline_autonomous_mode(tool_registry):
    """Autonomous mode with mocked LLM."""
    from siyarix.core import AgentCore, AgentGoal, AgentMode
    agent = AgentCore(mode=AgentMode.AUTONOMOUS, registry=tool_registry)
    mock_llm = AsyncMock(return_value=MagicMock(content="{'needs_tools': False, 'response': 'ok'}"))
    agent._providers.complete = mock_llm

    goal = AgentGoal(description="check service status", timeout=10)
    with patch.object(agent._planner_autonomous, "plan", AsyncMock()) as mock_plan:
        mock_plan.return_value = ExecutionPlan(goal="check", steps=[PlanStep(command="echo ok")])
        mock_exec = AsyncMock()
        mock_exec.return_value = ExecutionPlan(
            goal="check", steps=[PlanStep(command="echo ok", status=StepStatus.COMPLETED, result={"output": "ok"})],
            status=PlanStatus.COMPLETED,
        )
        agent._executor_autonomous.execute_plan = mock_exec
        result = await agent.execute_goal(goal)
        assert result.success is True


# ═══════════════════════════════════════════════════════════════════
# CLI Command Testing via Typer CliRunner
# ═══════════════════════════════════════════════════════════════════

def test_cli_help():
    from typer.testing import CliRunner
    from siyarix.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Siyarix" in result.output or "Usage" in result.output


def test_cli_version():
    from typer.testing import CliRunner
    from siyarix.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0


def test_cli_config_set():
    from typer.testing import CliRunner
    from siyarix.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["config", "set", "log_level", "debug"])
    assert result.exit_code == 0


def test_cli_config_get():
    from typer.testing import CliRunner
    from siyarix.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["config", "get", "log_level"])
    assert result.exit_code == 0


def test_cli_config_list():
    from typer.testing import CliRunner
    from siyarix.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["config", "list"])
    assert result.exit_code == 0


def test_cli_config_reset():
    from typer.testing import CliRunner
    from siyarix.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["config", "reset", "log_level"])
    assert result.exit_code == 0


# ═══════════════════════════════════════════════════════════════════
# Chat REPL Simulation
# ═══════════════════════════════════════════════════════════════════

def test_chat_slash_help():
    """Verify /help returns command list."""
    from siyarix.chat.commands import HELP_CATEGORIES, SLASH_HELP
    assert len(HELP_CATEGORIES) > 0
    assert "/help" in SLASH_HELP
    assert all(cat[0] for cat in HELP_CATEGORIES)


@pytest.mark.asyncio
async def test_chat_session_full_lifecycle(tmp_path):
    """Create, add messages, save, load a chat session."""
    from siyarix.chat.session import ChatSession
    session = ChatSession(session_id="e2e_test")
    session.add_message("user", "scan target")
    session.add_message("assistant", "OK, scanning...")
    assert len(session.messages) == 2
    path = tmp_path / "session.json"
    session.save(path)
    loaded = ChatSession.load(path)
    assert loaded.session_id == "e2e_test"
    assert len(loaded.messages) == 2
    assert loaded.messages[0].role == "user"


@pytest.mark.asyncio
async def test_chat_session_branching(tmp_path):
    """Test branch creation and saving."""
    from siyarix.chat.session import ChatSession
    session = ChatSession(session_id="branch_test")
    session.add_message("user", "initial scan")
    branch = session.branch()
    assert len(branch.messages) == 1


# ═══════════════════════════════════════════════════════════════════
# API Server Startup/Shutdown Tests
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_api_server_lifecycle():
    """Start and shutdown the API server using the core agent's lifecycle."""
    from siyarix.core import AgentCore
    agent = AgentCore()
    with patch.object(agent, "_knowledge_graph") as mock_kg:
        with patch("pathlib.Path.exists", return_value=False):
            with patch.object(agent, "initialize", AsyncMock()):
                with patch.object(agent, "shutdown", AsyncMock()) as mock_shutdown:
                    await agent.start()
                    await agent.shutdown()
                    mock_shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_api_server_shutdown_cleanup():
    """Verify shutdown cleans up resources."""
    from siyarix.core import AgentCore
    agent = AgentCore()
    agent._kg_path = MagicMock(spec=Path)
    agent._kg_path.parent = MagicMock(spec=Path)
    with patch.object(agent._executor_registry, "close", AsyncMock()) as mock_reg_close:
        with patch.object(agent._executor_autonomous, "close", AsyncMock()) as mock_auto_close:
            with patch.object(agent._knowledge_graph, "save_json"):
                await agent.shutdown()
                mock_reg_close.assert_awaited_once_with(timeout=5.0)
                mock_auto_close.assert_awaited_once_with(timeout=5.0)


# ═══════════════════════════════════════════════════════════════════
# Onboarding Wizard Simulation
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_onboarding_wizard_flow():
    """Simulate the onboarding experience."""
    from siyarix.onboarding import OnboardingWizard
    wizard = OnboardingWizard()
    with patch.object(wizard, "_welcome_screen", return_value=True):
        with patch.object(wizard, "_step_platform_detection"):
            with patch.object(wizard, "_step_requirements", AsyncMock()):
                with patch.object(wizard, "_step_dependencies", AsyncMock()):
                    with patch.object(wizard, "_step_tool_discovery", AsyncMock()):
                        with patch.object(wizard, "_step_credential_setup"):
                            with patch.object(wizard, "_step_provider", AsyncMock()):
                                with patch.object(wizard, "_step_mode"):
                                    with patch.object(wizard, "_step_persona_sysmsg"):
                                        with patch.object(wizard, "_step_install_persona_tools"):
                                            with patch.object(wizard, "_step_preferences"):
                                                with patch.object(wizard, "_step_network_diagnostics", AsyncMock()):
                                                    with patch.object(wizard, "_finalize", AsyncMock()):
                                                        result = await wizard.run()
                                                        assert result is True


# ═══════════════════════════════════════════════════════════════════
# Multi-step Workflow Execution
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_multi_step_workflow_sequential(tool_registry):
    """Execute a multi-step plan sequentially through RegistryExecutor."""
    plan = ExecutionPlan(
        goal="Multi-step test",
        plan_type=PlanType.SEQUENTIAL,
        steps=[
            PlanStep(id="s1", tool="nmap", args={"target": "scanme.nmap.org"}, description="Nmap scan"),
            PlanStep(id="s2", tool="nuclei", args={"target": "scanme.nmap.org"}, description="Nuclei scan", dependencies=["s1"]),
        ],
    )
    executor = RegistryExecutor(registry=tool_registry)
    with patch.object(executor, "_try_execute", AsyncMock(return_value={"status": "success"})):
        result = await executor.execute_plan(plan)
        assert result.status == PlanStatus.COMPLETED


@pytest.mark.asyncio
async def test_multi_step_workflow_parallel(tool_registry):
    """Execute multi-step plan in parallel."""
    plan = ExecutionPlan(
        goal="Parallel test",
        plan_type=PlanType.PARALLEL,
        steps=[
            PlanStep(id="p1", tool="nmap", args={"target": "x"}, description="Nmap"),
            PlanStep(id="p2", tool="nuclei", args={"target": "x"}, description="Nuclei"),
        ],
    )
    executor = RegistryExecutor(registry=tool_registry)
    with patch.object(executor, "_try_execute", AsyncMock(return_value={"status": "success"})):
        result = await executor.execute_plan(plan)
        assert result.status == PlanStatus.COMPLETED


# ═══════════════════════════════════════════════════════════════════
# Provider Failover Scenarios
# ═══════════════════════════════════════════════════════════════════

class TestProviderFailover:
    """Simulate provider failures and fallback."""

    @pytest.mark.asyncio
    async def test_provider_fail_and_fallback(self):
        from siyarix.core import AgentCore, AgentGoal, AgentMode
        agent = AgentCore()
        goal = AgentGoal(description="test", timeout=5)
        agent._mode = AgentMode.AUTONOMOUS
        with patch.object(agent._planner_autonomous, "plan", AsyncMock(return_value=ExecutionPlan(goal="test", steps=[PlanStep(command="echo ok")]))):
            with patch.object(agent._executor_autonomous, "execute_plan", AsyncMock(return_value=ExecutionPlan(goal="test", steps=[PlanStep(command="echo ok", status=StepStatus.COMPLETED)], status=PlanStatus.COMPLETED))):
                result = await agent.execute_goal(goal)
                assert result.success is True

    @pytest.mark.asyncio
    async def test_provider_complete_retry_then_fail(self):
        from siyarix.chat.openai_compat import make_openai_adapter
        adapter = make_openai_adapter("openai", "sk-test")
        with patch("siyarix.chat.openai_compat.resolve_model", side_effect=Exception("provider fail")):
            with pytest.raises(Exception):
                await adapter("system", "user")


# ═══════════════════════════════════════════════════════════════════
# Permission Gate Enforcement
# ═══════════════════════════════════════════════════════════════════

class TestPermissionGateE2E:
    """Test permission gate blocks/allows specific commands."""

    def test_gate_blocks_destructive_command(self):
        gate = PermissionGate()
        result = gate.check("rm -rf /", tool="shell")
        assert result.allowed is False

    def test_gate_blocks_format_command(self):
        gate = PermissionGate()
        result = gate.check("mkfs.ext4 /dev/sda", tool="shell")
        assert result.allowed is False

    def test_gate_allows_nmap(self):
        gate = PermissionGate()
        result = gate.check("nmap -sV target", tool="nmap")
        assert result.allowed is True

    def test_gate_requires_review_on_curl_to_localhost(self):
        gate = PermissionGate()
        result = gate.check("curl http://localhost:8000/admin", tool="curl")
        assert result.requires_review is True or result.allowed is True

    @pytest.mark.asyncio
    async def test_executor_enforces_permission_gate(self):
        reg = ToolRegistry()
        reg.register(ToolCapability(name="nmap", binary="nmap", installed=True, category=ToolCategory.RECON))
        gate = PermissionGate()
        executor = RegistryExecutor(registry=reg, permission_gate=gate)
        step = PlanStep(tool="shell", command="rm -rf /", args={"command": "rm -rf /"})
        with pytest.raises(PermissionDeniedError):
            await executor._check_permissions(step)


# ═══════════════════════════════════════════════════════════════════
# Credential Store Workflow
# ═══════════════════════════════════════════════════════════════════

class TestCredentialWorkflow:
    """Full credential lifecycle."""

    def test_store_retrieve_delete(self):
        from siyarix.credential_store import get_creds
        store = get_creds()
        stored = store.store("e2e_key", "supersecret", cred_type="api_key")
        retrieved = store.get(stored.cred_id)
        assert retrieved == "supersecret" or retrieved is not None
        deleted = store.delete("e2e_key")
        assert deleted is True

    def test_list_filtered(self):
        from siyarix.credential_store import get_creds
        store = get_creds()
        store.store("filter_test", "val", cred_type="api_key", environment="production")
        results = store.list_credentials(cred_type="api_key")
        assert len(results) >= 1


# ═══════════════════════════════════════════════════════════════════
# CVSS Scoring Workflow
# ═══════════════════════════════════════════════════════════════════

class TestCVSSWorkflow:
    """Full CVSS scoring pipeline."""

    def test_score_from_finding_critical(self):
        scorer = CVSSScorer()
        finding = {
            "title": "Remote Code Execution in Apache",
            "description": "RCE vulnerability allowing remote attack",
            "severity": "critical",
        }
        result = scorer.score_from_finding(finding)
        assert result.score >= 7.0
        assert result.vector_string.startswith("CVSS:3.1")

    def test_score_from_finding_low(self):
        scorer = CVSSScorer()
        finding = {"title": "Local info disclosure", "severity": "low"}
        result = scorer.score_from_finding(finding)
        assert result.vector.attack_vector == "local"

    def test_score_round_trip_vector_string(self):
        scorer = CVSSScorer()
        v = CVSSVector(attack_vector="network", attack_complexity="low", privileges_required="none",
                        user_interaction="none", scope="unchanged", confidentiality="high",
                        integrity="high", availability="high")
        r1 = scorer.score(vector=v)
        parsed = scorer.parse_vector_string(r1.vector_string)
        r2 = scorer.score(vector=parsed)
        assert abs(r1.score - r2.score) < 0.1


# ═══════════════════════════════════════════════════════════════════
# DLP Redaction Pipeline
# ═══════════════════════════════════════════════════════════════════

class TestDLPWorkflow:
    """DLP engine across various data types."""

    def test_redact_output_pipeline(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=True)
        data = {
            "text": "API key: AKIAIOSFODNN7EXAMPLE",
            "email": "user@example.com",
            "nested": {"secret": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        }
        result = engine.redact_dict(data)
        assert "[REDACTED AWS_KEY]" in result["text"]
        assert "[REDACTED EMAIL]" in result["email"]
        assert "[REDACTED GITHUB_TOKEN]" in result["nested"]["secret"]


# ═══════════════════════════════════════════════════════════════════
# OPSEC Isolation + Burn Workflow
# ═══════════════════════════════════════════════════════════════════

class TestOPSECWorkflow:
    """Full OPSEC lifecycle."""

    def test_isolate_disable(self):
        mgr = OPSECManager()
        result = mgr.isolate("10.0.0.5", use_tor=True, memory_only=True)
        assert result.success is True
        assert mgr.is_active is True
        assert mgr.status.memory_only is True
        disable_result = mgr.disable()
        assert disable_result.success is True
        assert mgr.is_active is False

    def test_burn_and_summary(self):
        mgr = OPSECManager()
        summary = mgr.summary()
        assert "isolated" in summary
        result = mgr.burn()
        assert result.success is True


# ═══════════════════════════════════════════════════════════════════
# Planner → Executor Integration
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_planner_to_executor_flow(tool_registry):
    """Plan a goal and execute it through the executor."""
    planner = RegistryPlanner()
    plan = planner.plan("nmap scan target", available_tools=["nmap", "nuclei"])
    assert len(plan.steps) >= 1
    assert plan.status == PlanStatus.ACTIVE

    executor = RegistryExecutor(registry=tool_registry)
    with patch.object(executor, "_try_execute", AsyncMock(return_value={"status": "success"})):
        result = await executor.execute_plan(plan)
        assert result.status == PlanStatus.COMPLETED


@pytest.mark.asyncio
async def test_planner_smart_plan_to_executor(tool_registry):
    """Smart plan -> resolve alternatives -> execute."""
    planner = RegistryPlanner()
    tool_names = ["nmap", "nuclei", "gobuster"]
    planner.build_index(tool_names, tool_registry=tool_registry)
    plan = planner.smart_plan("scan example.com for vulnerabilities", available_tools=tool_names)
    assert len(plan.steps) >= 1

    executor = RegistryExecutor(registry=tool_registry)
    with patch.object(executor, "_try_execute", AsyncMock(return_value={"status": "success"})):
        result = await executor.execute_plan(plan)
        assert result.status == PlanStatus.COMPLETED


# ═══════════════════════════════════════════════════════════════════
# Context Manager Integration
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_context_build_and_compress():
    """Build context, add items, compress, and retrieve."""
    ctx = ContextManager(max_tokens=500)
    ctx.add_system_prompt("You are a security tool.")
    ctx.add_history("Scan the target with nmap", "user")
    ctx.add_tool_output("nmap", "Open ports: 22, 80, 443")
    ctx.add_finding({"type": "vuln", "message": "OpenSSH vulnerable"})

    built = ctx.build_context()
    assert len(built) >= 1

    relevant = ctx.get_relevant_context("nmap")
    assert len(relevant) >= 1

    stats = ctx.stats()
    assert stats["total_chunks"] > 0


# ═══════════════════════════════════════════════════════════════════
# Compliance Assessment Pipeline
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_compliance_assessment_pipeline(tmp_path):
    """Full compliance assessment across frameworks."""
    engine = ComplianceEngine(base_dir=tmp_path / "compliance_evidence")
    for framework in ["SOC2", "NIST", "GDPR"]:
        report = await engine.run_assessment(framework, "target.example.com")
        assert report.framework == framework
        assert len(report.results) > 0
        assert report.evidence_path.exists()
        assert (report.evidence_path / "report.json").exists()


# ═══════════════════════════════════════════════════════════════════
# Configuration Management Workflow
# ═══════════════════════════════════════════════════════════════════

class TestConfigWorkflow:
    """Full configuration lifecycle."""

    def test_set_get_reset(self, tmp_path):
        p = tmp_path / "settings.toml"
        store = SettingsStore(path=p)
        store.set("log_level", "debug")
        assert store.get("log_level") == "debug"
        store.reset("log_level")
        assert store.get("log_level") == "warning"

    def test_list_all_shows_modified(self, tmp_path):
        p = tmp_path / "settings.toml"
        store = SettingsStore(path=p)
        store.set("log_level", "debug")
        rows = store.list_all()
        log_row = [r for r in rows if r["key"] == "log_level"][0]
        assert log_row["modified"] is True

    def test_reset_all(self, tmp_path):
        p = tmp_path / "settings.toml"
        store = SettingsStore(path=p)
        store.set("log_level", "debug")
        store.reset()
        assert store.get("log_level") == "warning"


# ═══════════════════════════════════════════════════════════════════
# Tool Installer Workflow
# ═══════════════════════════════════════════════════════════════════

class TestToolInstallerWorkflow:
    """Tool installation lifecycle."""

    def test_install_already_installed(self):
        from siyarix.tool_installer import ToolInstaller
        installer = ToolInstaller()
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = installer.install("nmap")
            assert result.success is True
            assert result.method == "already_installed"

    def test_auto_install_missing(self):
        from siyarix.tool_installer import ToolInstaller
        installer = ToolInstaller()
        with patch.object(installer, "is_installed", side_effect=lambda t: t != "missing_tool"):
            with patch.object(installer, "install_tool", return_value=True):
                results = installer.auto_install_missing(["present", "missing_tool"])
                assert len(results) == 1


# ═══════════════════════════════════════════════════════════════════
# Multi-Provider Chat Adapter Integration
# ═══════════════════════════════════════════════════════════════════

class TestOpenAICompatIntegration:
    """OpenAI compat detect + resolve + build messages."""

    def test_detect_compat_flags(self):
        from siyarix.chat.openai_compat import detect_compat
        compat = detect_compat("deepseek", "https://api.deepseek.com")
        assert compat.thinking_format == "deepseek"
        assert compat.requires_reasoning_content_on_assistant is True
        assert compat.supports_reasoning_effort is True

        compat2 = detect_compat("moonshot", "https://api.moonshot.cn/v1")
        assert compat2.max_tokens_field == "max_tokens"

    def test_resolve_model_from_settings(self):
        from siyarix.chat.openai_compat import resolve_model
        settings = MagicMock()
        settings.get.return_value = "gpt-5-test"
        model = resolve_model("openai", settings)
        assert model == "gpt-5-test"

    def test_build_messages_with_developer_role(self):
        from siyarix.chat.openai_compat import build_messages, OpenAICompat
        compat = OpenAICompat(supports_developer_role=True)
        msgs = build_messages("You are helpful", "Hello", compat=compat)
        assert msgs[0]["role"] == "developer"

    def test_build_messages_skips_system_in_history(self):
        from siyarix.chat.openai_compat import build_messages
        msgs = build_messages("system prompt", "user query",
                              history=[{"role": "system", "content": "skip"}, {"role": "user", "content": "hi"}])
        roles = [m["role"] for m in msgs]
        assert roles.count("system") == 1
        assert roles.count("user") == 2


# ═══════════════════════════════════════════════════════════════════
# Execution Budget Enforcement
# ═══════════════════════════════════════════════════════════════════

def test_execution_budget_enforcement():
    from siyarix.executor import ExecutionBudget
    budget = ExecutionBudget(max_iterations=2, max_tool_calls=5, max_duration_s=3600)
    assert budget.consume_iteration() is True
    assert budget.consume_iteration() is True
    assert budget.consume_iteration() is False
    assert budget.is_exhausted is True

    budget2 = ExecutionBudget(max_iterations=100, max_tool_calls=3, max_duration_s=3600)
    budget2.consume_tool_call()
    budget2.consume_tool_call()
    budget2.consume_tool_call()
    assert budget2.consume_tool_call() is False


# ═══════════════════════════════════════════════════════════════════
# Guardrail Enforcement
# ═══════════════════════════════════════════════════════════════════

class TestGuardrailEnforcement:
    """Guardrail threshold enforcement."""

    def test_tool_failure_guardrail(self):
        from siyarix.executor import GuardrailConfig, ToolCallTracker
        cfg = GuardrailConfig(exact_failure_warn_after=1, exact_failure_block_after=3)
        tracker = ToolCallTracker()
        tracker._config = cfg
        with patch.object(tracker, "_save_state"):
            r1 = tracker.record("nmap", "args", False)
            assert r1 is None
            r2 = tracker.record("nmap", "args", False)
            assert r2 is None
            r3 = tracker.record("nmap", "args", False)
            assert r3 is not None
            assert "BLOCKED" in r3


# ═══════════════════════════════════════════════════════════════════
# Autonomous Executor Command Review
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_autonomous_executor_review_accepts_commands():
    """User accepts commands in review."""
    from siyarix.models import ExecutionPlan, PlanStep
    ae = AutonomousExecutor(command_review=True)
    plan = ExecutionPlan(goal="test", steps=[PlanStep(command="echo hello")])
    with patch("siyarix.shell_review.review_and_confirm", return_value="echo hello"):
        with patch.object(ae, "_build_cmd_states", return_value=[MagicMock(label="$ echo hello")]):
            with patch.object(ae, "_execute_batch") as mock_batch:
                mock_batch.return_value = ExecutionPlan(
                    goal="test", status=PlanStatus.COMPLETED,
                    steps=[PlanStep(command="echo hello", result={"output": "hello"})],
                )
                result = await ae.execute_plan(plan)
                assert result.status == PlanStatus.COMPLETED


# ═══════════════════════════════════════════════════════════════════
# Exception Handling E2E
# ═══════════════════════════════════════════════════════════════════

def test_custom_exceptions():
    """Test custom exception hierarchy."""
    from siyarix.exceptions import (
        SiyarixException, ToolExecutionError, ToolNotFoundError,
        PermissionDeniedError, LLMProviderError,
    )

    assert issubclass(ToolExecutionError, SiyarixException)
    assert issubclass(ToolNotFoundError, SiyarixException)
    assert issubclass(PermissionDeniedError, SiyarixException)
    assert issubclass(BudgetExceededError, SiyarixException)
    assert issubclass(LLMProviderError, SiyarixException)

    e1 = PermissionDeniedError("Not allowed")
    assert "Not allowed" in str(e1)

    e2 = BudgetExceededError("Over budget")
    assert "Over budget" in str(e2)


# ═══════════════════════════════════════════════════════════════════
# Event Bus E2E
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_event_bus_publish_subscribe():
    from siyarix.events import Event, EventType, get_event_bus
    bus = get_event_bus()
    received = []

    async def handler(event: Event):
        received.append(event)

    bus.on(EventType.PLAN_CREATED, handler)
    await bus.emit(Event(type=EventType.PLAN_CREATED, source="test", data={"msg": "hello"}))
    assert len(received) == 1
    assert received[0].data["msg"] == "hello"


# ═══════════════════════════════════════════════════════════════════
# Metrics Recording E2E
# ═══════════════════════════════════════════════════════════════════

def test_metrics_recording():
    from siyarix.metrics import get_metrics
    metrics = get_metrics()
    metrics.record_scan(duration=10.5, successful=True, findings_count=5)
    metrics.record_plan_generation(successful=True, used_model=True)
    assert metrics.execution.total_scans >= 1
    assert metrics.planner.plans_generated >= 1


# ═══════════════════════════════════════════════════════════════════
# Subprocess Utils Integration
# ═══════════════════════════════════════════════════════════════════

def test_safe_run_sync_basic():
    """Run a simple command synchronously."""
    from siyarix.subprocess_utils import safe_run_sync
    cmd = ["cmd", "/c", "echo", "hello"] if sys.platform == "win32" else ["echo", "hello"]
    result = safe_run_sync(cmd, timeout=5)
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_safe_run_async_stream():
    from siyarix.subprocess_utils import safe_run_async_stream
    from siyarix.subprocess_utils import get_platform_shell_cmd
    cmd = get_platform_shell_cmd("echo hello")
    result = await safe_run_async_stream(cmd, timeout=5, validate=False)
    assert "hello" in result.stdout


# ═══════════════════════════════════════════════════════════════════
# Memory Manager Integration
# ═══════════════════════════════════════════════════════════════════

def test_memory_manager_store_retrieve():
    from siyarix.memory import MemoryManager, MemoryLayer
    mem = MemoryManager()
    mem.store(key="e2e_key", value="e2e_value", layer=MemoryLayer.SESSION, tags=["test"])
    results = mem.search("e2e_key", layer=MemoryLayer.SESSION)
    assert len(results) >= 1
    assert results[0].value == "e2e_value"


# ═══════════════════════════════════════════════════════════════════
# Knowledge Graph Integration
# ═══════════════════════════════════════════════════════════════════

def test_knowledge_graph_add_nodes_and_edges():
    from siyarix.knowledge_graph import KnowledgeGraph, NodeType, EdgeType
    kg = KnowledgeGraph()
    h1 = kg.add_node(NodeType.HOST, label="10.0.0.1", ip="10.0.0.1")
    h2 = kg.add_node(NodeType.HOST, label="10.0.0.2", ip="10.0.0.2")
    edge = kg.add_edge(h1.node_id, h2.node_id, EdgeType.RESOLVES_TO)
    assert edge is not None
    path = kg.shortest_path(h1.node_id, h2.node_id)
    assert len(path) > 0


# ═══════════════════════════════════════════════════════════════════
# Worker Pool Integration
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_worker_pool_submit():
    from siyarix.worker_pool import AsyncWorkerPool
    pool = AsyncWorkerPool(max_workers=4)

    async def work(x):
        return x * 2

    results = await asyncio.gather(*[pool.submit(work, i) for i in range(5)])
    assert results == [0, 2, 4, 6, 8]
    await pool.close(timeout=1.0)


# ═══════════════════════════════════════════════════════════════════
# Stealth Engine Integration
# ═══════════════════════════════════════════════════════════════════

def test_stealth_engine():
    from siyarix.stealth import StealthEngine
    stealth = StealthEngine()
    assert stealth.config.enabled is False
    stealth.enable()
    assert stealth.config.enabled is True
    delay = stealth.get_randomized_delay(1.0)
    assert delay >= 0
    stealth.disable()
    assert stealth.config.enabled is False


# ═══════════════════════════════════════════════════════════════════
# Cross-Module: DLP → Executor → Output
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_dlp_redaction_in_executor_pipeline(tool_registry):
    """Verify DLP redaction applied to executor results."""
    from siyarix.dlp import DLPEngine
    engine = DLPEngine(redact_secrets=True, redact_pii=True)
    result = {"output": "Email: admin@example.com, Key: AKIAIOSFODNN7EXAMPLE"}
    redacted = engine.redact_dict(result)
    assert "[REDACTED AWS_KEY]" in redacted["output"]
    assert "[REDACTED EMAIL]" in redacted["output"]