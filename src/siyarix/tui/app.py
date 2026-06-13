# SPDX-License-Identifier: AGPL-3.0-or-later
"""Textual-based Terminal User Interface for Siyarix."""

from __future__ import annotations

import asyncio
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Input, RichLog, DataTable, Static
from textual import work

from siyarix.core import AgentCore, AgentGoal
from siyarix.events import get_event_bus, EventType


class SiyarixTUI(App[None]):
    """Siyarix TUI Application."""

    CSS = """
    #chat-log {
        height: 1fr;
        border: solid green;
    }
    #input {
        dock: bottom;
    }
    #findings-table {
        height: 1fr;
        width: 40%;
        border: solid cyan;
    }
    .panel {
        height: 100%;
    }
    """

    TITLE = "Siyarix - Offensive Security AI"

    def __init__(self, core: AgentCore) -> None:
        super().__init__()
        self.core = core
        self.bus = get_event_bus()
        self.chat_log = RichLog(id="chat-log", markup=True)
        self.findings_table = DataTable(id="findings-table")
        self.input_widget = Input(placeholder="Enter command or goal...", id="input")

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(classes="panel"):
                yield self.chat_log
                yield self.input_widget
            yield self.findings_table
        yield Footer()

    def on_mount(self) -> None:
        self.findings_table.add_columns("ID", "Type", "Severity")
        self.bus.on(None, self.on_agent_event)
        self.chat_log.write("[bold green]Siyarix OS[/bold green] initialized.")
        self.chat_log.write("Type a command and press Enter.")

    async def on_agent_event(self, event: Any) -> None:
        # Handle events from the event bus and update UI
        if event.type == EventType.CUSTOM and event.data.get("sub_type") == "text_end":
            self.call_from_thread(self.chat_log.write, f"[bold blue]Agent:[/bold blue] {event.data.get('text', '')}")
        elif event.type == EventType.CUSTOM and event.data.get("sub_type") == "finding":
            finding = event.data.get("finding", {})
            self.call_from_thread(
                self.findings_table.add_row,
                finding.get("id", "N/A"),
                finding.get("type", "N/A"),
                finding.get("severity", "info")
            )
        elif event.type == EventType.TOOL_EXECUTING:
            tool = event.data.get("tool", "")
            self.call_from_thread(self.chat_log.write, f"[dim italic]Executing tool: {tool}...[/dim italic]")
        elif event.type == EventType.AGENT_ERROR:
            self.call_from_thread(self.chat_log.write, f"[bold red]Error:[/bold red] {event.data.get('error', '')}")

    @work(exclusive=True, thread=False)
    async def process_command(self, text: str) -> None:
        self.chat_log.write(f"\n[bold magenta]User:[/bold magenta] {text}")
        try:
            goal = AgentGoal(description=text)
            await self.core.execute_goal(goal)
            self.chat_log.write("[bold green]Execution complete.[/bold green]")
        except Exception as e:
            self.chat_log.write(f"[bold red]System Error: {e}[/bold red]")

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        if not message.value.strip():
            return
        text = message.value
        self.input_widget.value = ""
        self.process_command(text)

