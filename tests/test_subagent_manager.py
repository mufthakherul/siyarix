# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for SubagentManager, subagent models, SplitPane working window, and /agent commands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, AsyncMock
import pytest

from siyarix.chat.subagents import (
    SubagentRole,
    SubagentStatus,
    SubagentTask,
    SubagentRecord,
    SubagentManager,
)
from siyarix.chat.ui import SplitPane, SmartAutocomplete
from siyarix.chat.prompts import make_bottom_toolbar, make_prompt_top
from siyarix.chat.repl import SiyarixChat
from prompt_toolkit.document import Document


# ── Subagent Model Tests ───────────────────────────────────────────────


class TestSubagentModels:
    def test_record_creation_and_defaults(self) -> None:
        rec = SubagentRecord(
            id="recon-1",
            role=SubagentRole.RECON,
            goal="Identify subdomains of target.com",
        )
        assert rec.id == "recon-1"
        assert rec.role == SubagentRole.RECON
        assert rec.status == SubagentStatus.IDLE
        assert rec.progress == 0.0
        assert rec.tasks == []
        assert rec.findings == []
        assert rec.logs == []

    def test_record_logging_and_tasks(self) -> None:
        rec = SubagentRecord(id="scanner-1", role=SubagentRole.SCANNER, goal="Port scan")
        rec.add_log("Starting scan")
        assert len(rec.logs) == 1
        assert "Starting scan" in rec.logs[0]

        task = SubagentTask(
            id="step_1",
            description="nmap scan",
            tool="nmap",
            status="completed",
            output="Port 80 open",
        )
        rec.add_task(task)
        assert len(rec.tasks) == 1
        assert rec.current_step == "nmap scan"

        rec.add_finding({"title": "Open Port 80", "severity": "info"})
        assert len(rec.findings) == 1
        assert "Finding discovered: Open Port 80" in rec.logs[-1]

    def test_record_to_dict(self) -> None:
        rec = SubagentRecord(id="agent-1", role=SubagentRole.GENERAL, goal="Analyze security")
        data = rec.to_dict()
        assert data["id"] == "agent-1"
        assert data["role"] == "general"
        assert data["status"] == "idle"
        assert data["findings_count"] == 0


# ── SubagentManager Lifecycle Tests ────────────────────────────────────


class TestSubagentManager:
    def test_spawn_and_get(self) -> None:
        mgr = SubagentManager()
        rec = mgr.spawn(goal="Find subdomains", role="recon")
        assert rec.id.startswith("recon-")
        assert rec.role == SubagentRole.RECON
        assert mgr.active_id == rec.id
        assert mgr.get(rec.id) is rec

    def test_custom_id_spawn(self) -> None:
        mgr = SubagentManager()
        rec = mgr.spawn(goal="Custom test", role="scanner", custom_id="custom-scanner")
        assert rec.id == "custom-scanner"
        assert mgr.get("custom-scanner") is rec

    def test_switch_and_cycle(self) -> None:
        mgr = SubagentManager()
        r1 = mgr.spawn(goal="Task 1", role="recon", custom_id="agent-1")
        r2 = mgr.spawn(goal="Task 2", role="exploit", custom_id="agent-2")

        # By default active is agent-1 (first spawned)
        assert mgr.active_id == "agent-1"

        # Switch to agent-2
        assert mgr.switch("agent-2") is True
        assert mgr.active_id == "agent-2"

        # Switch to nonexistent
        assert mgr.switch("agent-999") is False
        assert mgr.active_id == "agent-2"

        # Cycle focus
        cycled = mgr.cycle_active()
        assert cycled.id == "agent-1"
        cycled2 = mgr.cycle_active()
        assert cycled2.id == "agent-2"

    def test_clear_completed_and_cancelled(self) -> None:
        mgr = SubagentManager()
        r1 = mgr.spawn(goal="Task 1", custom_id="sub-1")
        r2 = mgr.spawn(goal="Task 2", custom_id="sub-2")
        r3 = mgr.spawn(goal="Task 3", custom_id="sub-3")

        r1.status = SubagentStatus.COMPLETED
        r2.status = SubagentStatus.RUNNING
        r3.status = SubagentStatus.FAILED

        cleared = mgr.clear()
        assert cleared == 2
        remaining = mgr.list_subagents()
        assert len(remaining) == 1
        assert remaining[0].id == "sub-2"

    def test_render_table_and_preview(self) -> None:
        mgr = SubagentManager()
        rec = mgr.spawn(goal="DNS enumeration", role="recon", custom_id="recon-test")
        rec.add_finding({"title": "Subdomain takeover", "severity": "high"})
        rec.add_task(
            SubagentTask(id="1", description="dnsrecon", tool="dnsrecon", status="completed")
        )

        table = mgr.render_table()
        assert table is not None
        assert table.title == "Siyarix Subagent Fleet"

        preview = mgr.render_preview("recon-test")
        assert preview is not None
        assert "recon-test" in str(preview.title)


# ── SplitPane Enhanced Views Tests ─────────────────────────────────────


class TestSplitPaneViews:
    def test_split_pane_subagents_view(self) -> None:
        pane = SplitPane()
        mgr = SubagentManager()
        r = mgr.spawn(goal="Recon target", role="recon", custom_id="recon-view")
        layout_str = pane.generate_layout(
            right_type="subagents",
            subagents=mgr.list_subagents(),
        )
        assert "Subagent Fleet" in layout_str
        assert "recon-view" in layout_str

    def test_split_pane_tasks_view(self) -> None:
        pane = SplitPane()
        tasks = [
            {"description": "Nmap port scan", "status": "completed", "tool": "nmap"},
            {"description": "Nikto web audit", "status": "running", "tool": "nikto"},
        ]
        layout_str = pane.generate_layout(
            right_type="tasks",
            tasks=tasks,
        )
        assert "Execution Tasks" in layout_str
        assert "Nmap port scan" in layout_str

    def test_split_pane_findings_view(self) -> None:
        pane = SplitPane()
        findings = [
            {"title": "SQL Injection in /api/login", "severity": "critical"},
            {"title": "Missing Security Headers", "severity": "low"},
        ]
        layout_str = pane.generate_layout(
            right_type="findings",
            findings=findings,
        )
        assert "Discovered Findings" in layout_str
        assert "SQL Injection" in layout_str

    def test_split_pane_logs_view(self) -> None:
        pane = SplitPane()
        logs = ["$ nmap -sT 10.0.0.1", "Host is up (0.001s latency)", "PORT 80/tcp OPEN"]
        layout_str = pane.generate_layout(
            right_type="logs",
            logs=logs,
        )
        assert "Console Log Tail" in layout_str
        assert "nmap -sT" in layout_str


# ── /agent and /split Handler Tests ────────────────────────────────────


@pytest.fixture
def chat_instance():
    return SiyarixChat()


@pytest.fixture
def mock_console():
    from siyarix.chat.console import console

    with patch.object(console, "print") as mock_print:
        yield MagicMock(print=mock_print)


@pytest.mark.asyncio
async def test_cmd_agent_list_empty(chat_instance, mock_console):
    await chat_instance._cmd_agent("list")
    mock_console.print.assert_called_once()
    assert "No subagents spawned yet" in mock_console.print.call_args[0][0]


@pytest.mark.asyncio
async def test_cmd_agent_spawn_and_list(chat_instance, mock_console):
    with patch.object(chat_instance.subagent_mgr, "run_foreground", new_callable=AsyncMock):
        await chat_instance._cmd_agent("spawn recon discover subdomains")
        subagents = chat_instance.subagent_mgr.list_subagents()
        assert len(subagents) == 1
        assert subagents[0].role == SubagentRole.RECON
        assert "discover subdomains" in subagents[0].goal

    # Now listing shows the table
    await chat_instance._cmd_agent("list")
    assert mock_console.print.call_count >= 2


@pytest.mark.asyncio
async def test_cmd_agent_switch(chat_instance, mock_console):
    chat_instance.subagent_mgr.spawn(goal="G1", role="recon", custom_id="agent-recon")
    chat_instance.subagent_mgr.spawn(goal="G2", role="exploit", custom_id="agent-exploit")

    await chat_instance._cmd_agent("switch agent-exploit")
    assert chat_instance.subagent_mgr.active_id == "agent-exploit"


@pytest.mark.asyncio
async def test_cmd_agent_preview_and_status(chat_instance, mock_console):
    chat_instance.subagent_mgr.spawn(goal="Test goal", role="scanner", custom_id="agent-scan")
    await chat_instance._cmd_agent("preview agent-scan")
    assert mock_console.print.called

    await chat_instance._cmd_agent("status")
    assert mock_console.print.called


def test_cmd_split_cycle_views(chat_instance, mock_console):
    # Enable with specific view
    chat_instance._cmd_split("subagents")
    assert chat_instance._split_pane_enabled is True
    assert chat_instance._split_pane_type == "subagents"

    # Cycle view
    chat_instance._cmd_split("")
    assert chat_instance._split_pane_enabled is True
    assert chat_instance._split_pane_type == "tasks"

    # Disable
    chat_instance._cmd_split("off")
    assert chat_instance._split_pane_enabled is False


# ── Prompts and Autocomplete Tests ────────────────────────────────────


def test_bottom_toolbar_with_subagent():
    bar = make_bottom_toolbar(
        mode="autonomous",
        provider="gemini",
        session_id="abcdef",
        msg_count=5,
        subagent_id="recon-1",
        subagent_role="recon",
        subagent_status="running",
        split_view="subagents",
    )
    tokens_text = "".join(t[1] for t in bar)
    assert "agent:recon-1" in tokens_text
    assert "split:subagents" in tokens_text
    assert "Alt+W:split" in tokens_text
    assert "Alt+A:agent" in tokens_text


def test_prompt_top_with_subagent():
    top = make_prompt_top(
        mode="autonomous",
        provider="gemini",
        session_id="abcdef",
        msg_count=3,
        uptime_seconds=120.0,
        subagent_id="recon-1",
    )
    top_plain = top.plain if hasattr(top, "plain") else str(top)
    assert "[agent:recon-1]" in top_plain


def test_autocomplete_agent_and_split():
    mock_session = MagicMock()
    mock_mgr = SubagentManager()
    mock_mgr.spawn(goal="Scan", role="scanner", custom_id="test-scan-1")
    mock_session.subagent_manager = mock_mgr

    completer = SmartAutocomplete(session=mock_session)

    # Test /agent completions
    doc = Document("/agent ")
    completions = [c.text for c in completer.get_completions(doc, None)]
    assert "run" in completions
    assert "spawn" in completions
    assert "list" in completions
    assert "switch" in completions
    assert "preview" in completions

    # Test /split completions
    doc_split = Document("/split ")
    split_completions = [c.text for c in completer.get_completions(doc_split, None)]
    assert "subagents" in split_completions
    assert "tasks" in split_completions
    assert "findings" in split_completions
    assert "logs" in split_completions
