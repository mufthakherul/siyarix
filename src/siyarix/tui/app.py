# SPDX-License-Identifier: AGPL-3.0-or-later
"""Textual-based Terminal User Interface for Siyarix.

This premium dashboard provides real-time insights into agent execution,
vulnerability findings, live metrics, and network architecture.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

from textual.app import App, ComposeResult  # type: ignore
from textual.containers import Horizontal, Vertical, Container  # type: ignore
from textual.widgets import (  # type: ignore
    Header,
    Footer,
    Input,
    RichLog,
    DataTable,
    TabbedContent,
    TabPane,
    Tree,
    Sparkline,
    Static,
    Rule,
)
from textual import work  # type: ignore

from siyarix.core import AgentCore, AgentGoal
from siyarix.events import get_event_bus, EventType


class SiyarixTUI(App[None]):
    """Siyarix Advanced Command Center TUI."""

    CSS = """
    $primary: #00ffcc;
    $secondary: #ff00ff;
    $bg: #0d1117;
    $panel: #161b22;

    Screen {
        background: $bg;
    }

    Header {
        background: $panel;
        color: $primary;
        text-style: bold;
    }

    Footer {
        background: $panel;
        color: $secondary;
    }

    #sidebar {
        width: 30%;
        border-right: solid $primary;
        background: $panel;
        padding: 1;
    }

    #main-content {
        width: 70%;
        height: 100%;
    }

    #input {
        dock: bottom;
        border: round $primary;
        background: $panel;
    }

    .metric-panel {
        height: 8;
        border: solid $secondary;
        padding: 1;
        margin-bottom: 1;
    }

    DataTable {
        border: round $primary;
    }

    RichLog {
        border: round $secondary;
    }
    """

    TITLE = "SIYARIX | Advanced Offensive Security Orchestrator"

    def __init__(self, core: AgentCore) -> None:
        super().__init__()
        self.core = core
        self.bus = get_event_bus()
        self.chat_log = RichLog(id="chat-log", markup=True)
        self.findings_table = DataTable(id="findings-table")
        self.execution_tree = Tree("Execution Plan", id="exec-tree")
        self.input_widget = Input(placeholder="Deploy agent or enter query...", id="input")

        # Telemetry Widgets
        self.cpu_sparkline = Sparkline(summary_function=max, classes="spark")
        self.ram_sparkline = Sparkline(summary_function=max, classes="spark")
        self.telemetry_task: asyncio.Task[None] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            # Sidebar: Execution Tree & Telemetry
            with Vertical(id="sidebar"):
                yield Static("[bold #00ffcc]Execution Strategy[/]", classes="header")
                yield self.execution_tree
                yield Rule()

                yield Static("[bold #ff00ff]Live Telemetry[/]", classes="header")
                with Vertical(classes="metric-panel"):
                    yield Static("CPU Usage (%)")
                    yield self.cpu_sparkline
                with Vertical(classes="metric-panel"):
                    yield Static("Memory Usage (MB)")
                    yield self.ram_sparkline

            # Main Content: Tabs for Logs and Findings
            with Container(id="main-content"):
                with TabbedContent():
                    with TabPane("Terminal / Comms", id="tab-log"):
                        yield self.chat_log
                    with TabPane("Vulnerability Matrix", id="tab-findings"):
                        yield self.findings_table

                yield self.input_widget
        yield Footer()

    def on_mount(self) -> None:
        # Init table
        self.findings_table.add_columns("ID", "Category", "Severity", "Target")

        # Init Tree
        self.execution_tree.root.expand()
        self.execution_tree.root.add_leaf("Phase 1: Reconnaissance [Pending]")
        self.execution_tree.root.add_leaf("Phase 2: Vulnerability Analysis [Pending]")
        self.execution_tree.root.add_leaf("Phase 3: Exploitation [Pending]")

        # Hook events
        self.bus.on(None, self.on_agent_event)

        self.chat_log.write("[bold #00ffcc]Siyarix OS v2.0.0[/] successfully initialized.")
        self.chat_log.write("System online. Waiting for operator input...")

        # Start mock telemetry (to be wired to real metrics later)
        self.telemetry_task = asyncio.create_task(self.update_telemetry())

    async def update_telemetry(self) -> None:
        """Background task to update sparklines with live data."""
        cpu_data = [random.randint(5, 15) for _ in range(20)]
        ram_data = [random.randint(100, 150) for _ in range(20)]
        while True:
            # Simulate shifting data points
            cpu_data = cpu_data[1:] + [random.randint(10, 80)]
            ram_data = ram_data[1:] + [random.randint(100, 500)]
            self.cpu_sparkline.data = cpu_data
            self.ram_sparkline.data = ram_data
            await asyncio.sleep(1)

    async def on_agent_event(self, event: Any) -> None:
        # Handle events from the event bus and update UI
        if event.type == EventType.CUSTOM and event.data.get("sub_type") == "text_end":
            self.call_from_thread(
                self.chat_log.write, f"[[bold #ff00ff]SIYARIX[/]]: {event.data.get('text', '')}"
            )
        elif event.type == EventType.CUSTOM and event.data.get("sub_type") == "finding":
            finding = event.data.get("finding", {})
            self.call_from_thread(
                self.findings_table.add_row,
                finding.get("id", "N/A"),
                finding.get("type", "N/A"),
                finding.get("severity", "info"),
                finding.get("target", "global"),
            )
        elif event.type == EventType.TOOL_EXECUTING:
            tool = event.data.get("tool", "")
            self.call_from_thread(
                self.chat_log.write,
                f"[[dim #00ffcc]SYSTEM[/]] Executing module: [italic]{tool}[/italic]...",
            )
        elif event.type == EventType.AGENT_ERROR:
            self.call_from_thread(
                self.chat_log.write, f"[[bold red]CRITICAL[/]] {event.data.get('error', '')}"
            )

    @work(exclusive=True, thread=False)
    async def process_command(self, text: str) -> None:
        self.chat_log.write(f"\n[[bold white]OPERATOR[/]]: {text}")
        try:
            goal = AgentGoal(description=text)
            await self.core.execute_goal(goal)
            self.chat_log.write("[[bold #00ffcc]SYSTEM[/]] Execution complete.")
        except Exception as e:
            self.chat_log.write(f"[[bold red]SYSTEM FAULT[/]]: {e}")

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        if not message.value.strip():
            return
        text = message.value
        self.input_widget.value = ""
        self.process_command(text)
