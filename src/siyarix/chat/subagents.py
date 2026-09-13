# SPDX-License-Identifier: AGPL-3.0-or-later

"""Subagent lifecycle management, execution tracking, and previewing for Siyarix Chat.

Enables multi-agent coordination, specialized subagent delegation, background execution,
and rich side-by-side or tabular execution preview and switching.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import logging
from typing import Any

from rich.box import ROUNDED
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)


class SubagentRole(StrEnum):
    """Specialized roles for subagents."""

    RECON = "recon"
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    AUDITOR = "auditor"
    INTEL = "intel"
    REPORTER = "reporter"
    CODE_REVIEW = "code_review"
    GENERAL = "general"


class SubagentStatus(StrEnum):
    """Lifecycle status of a subagent."""

    IDLE = "idle"
    PLANNING = "planning"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SubagentTask:
    """Individual execution step or task tracked within a subagent."""

    id: str
    description: str
    tool: str = ""
    command: str = ""
    status: str = "pending"  # pending, running, completed, failed
    output: str = ""
    error: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "tool": self.tool,
            "command": self.command,
            "status": self.status,
            "output": self.output[:2000],
            "error": self.error[:1000],
            "duration_ms": self.duration_ms,
        }


@dataclass
class SubagentRecord:
    """State and execution record of an instantiated subagent."""

    id: str
    role: SubagentRole | str
    goal: str
    mode: str = "autonomous"
    status: SubagentStatus = SubagentStatus.IDLE
    progress: float = 0.0
    current_step: str = "Initialized"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_secs: float = 0.0
    tasks: list[SubagentTask] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    summary: str = ""
    error: str | None = None
    async_task: asyncio.Task[Any] | None = None

    def add_log(self, text: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.logs.append(f"[{ts}] {text}")
        if len(self.logs) > 500:
            self.logs = self.logs[-500:]

    def add_task(self, task: SubagentTask) -> None:
        self.tasks.append(task)
        self.current_step = task.description

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)
        self.add_log(
            f"Finding discovered: {finding.get('title', finding.get('type', 'Vulnerability'))}"
        )

    @property
    def elapsed(self) -> float:
        if self.duration_secs > 0:
            return self.duration_secs
        if self.started_at:
            end = self.completed_at or datetime.now(timezone.utc)
            return max(0.0, (end - self.started_at).total_seconds())
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": str(self.role),
            "goal": self.goal,
            "mode": self.mode,
            "status": str(self.status),
            "progress": self.progress,
            "current_step": self.current_step,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_secs": self.elapsed,
            "tasks": [t.to_dict() for t in self.tasks],
            "findings_count": len(self.findings),
            "logs_count": len(self.logs),
            "summary": self.summary,
            "error": self.error,
        }


class SubagentManager:
    """Manages subagent lifecycle, execution, switching, and previews."""

    def __init__(self) -> None:
        self._subagents: dict[str, SubagentRecord] = {}
        self._active_id: str | None = None
        self._counter: int = 0

    @property
    def active_id(self) -> str | None:
        return self._active_id

    @property
    def active_record(self) -> SubagentRecord | None:
        if self._active_id and self._active_id in self._subagents:
            return self._subagents[self._active_id]
        return None

    def list_subagents(self) -> list[SubagentRecord]:
        """Return all tracked subagent records sorted by creation order."""
        return list(self._subagents.values())

    def get(self, agent_id: str) -> SubagentRecord | None:
        """Get subagent record by exact or partial ID match."""
        if agent_id in self._subagents:
            return self._subagents[agent_id]
        # Partial prefix matching
        for k, v in self._subagents.items():
            if k.startswith(agent_id) or agent_id in k:
                return v
        return None

    def switch(self, agent_id: str) -> bool:
        """Switch active focus to a subagent."""
        rec = self.get(agent_id)
        if rec:
            self._active_id = rec.id
            return True
        return False

    def cycle_active(self) -> SubagentRecord | None:
        """Cycle focus to the next available subagent."""
        keys = list(self._subagents.keys())
        if not keys:
            self._active_id = None
            return None
        if self._active_id not in keys:
            self._active_id = keys[0]
        else:
            idx = keys.index(self._active_id)
            self._active_id = keys[(idx + 1) % len(keys)]
        return self._subagents[self._active_id]

    def cancel(self, agent_id: str) -> bool:
        """Cancel a running subagent task."""
        rec = self.get(agent_id)
        if not rec:
            return False
        if rec.async_task and not rec.async_task.done():
            rec.async_task.cancel()
            rec.status = SubagentStatus.CANCELLED
            rec.completed_at = datetime.now(timezone.utc)
            rec.add_log("Subagent task cancelled by user.")
            return True
        if rec.status in (SubagentStatus.RUNNING, SubagentStatus.PLANNING):
            rec.status = SubagentStatus.CANCELLED
            rec.completed_at = datetime.now(timezone.utc)
            rec.add_log("Subagent marked cancelled.")
            return True
        return False

    def clear(self, agent_id: str | None = None) -> int:
        """Clear completed or cancelled subagents from registry."""
        if agent_id:
            rec = self.get(agent_id)
            if rec and rec.id in self._subagents:
                del self._subagents[rec.id]
                if self._active_id == rec.id:
                    self._active_id = next(iter(self._subagents.keys()), None)
                return 1
            return 0

        to_remove = [
            k
            for k, v in self._subagents.items()
            if v.status
            in (SubagentStatus.COMPLETED, SubagentStatus.FAILED, SubagentStatus.CANCELLED)
        ]
        for k in to_remove:
            del self._subagents[k]
        if self._active_id not in self._subagents:
            self._active_id = next(iter(self._subagents.keys()), None)
        return len(to_remove)

    def spawn(
        self,
        goal: str,
        role: str = "general",
        mode: str = "autonomous",
        custom_id: str | None = None,
        background: bool = False,
        chat_session: Any = None,
    ) -> SubagentRecord:
        """Instantiate a new subagent and optionally launch execution."""
        self._counter += 1
        clean_role = role.lower().strip().replace("-", "_")
        try:
            role_enum = SubagentRole(clean_role)
        except ValueError:
            role_enum = SubagentRole.GENERAL

        agent_id = custom_id or f"{role_enum.value}-{self._counter}"
        # Ensure unique ID
        while agent_id in self._subagents:
            self._counter += 1
            agent_id = f"{role_enum.value}-{self._counter}"

        record = SubagentRecord(
            id=agent_id,
            role=role_enum,
            goal=goal,
            mode=mode,
            status=SubagentStatus.IDLE,
        )
        record.add_log(f"Subagent spawned with role '{role_enum.value}'. Goal: {goal}")
        self._subagents[agent_id] = record

        # Automatically focus on new subagent if none active
        if self._active_id is None:
            self._active_id = agent_id

        if background:
            record.async_task = asyncio.create_task(
                self._run_subagent(record, chat_session=chat_session)
            )

        return record

    async def run_foreground(
        self, record: SubagentRecord, chat_session: Any = None
    ) -> SubagentRecord:
        """Run subagent synchronously in the foreground."""
        return await self._run_subagent(record, chat_session=chat_session)

    async def _run_subagent(
        self, record: SubagentRecord, chat_session: Any = None
    ) -> SubagentRecord:
        """Execute the subagent lifecycle using AgentCore."""
        from ..core import AgentCore, AgentMode, AgentGoal

        record.status = SubagentStatus.PLANNING
        record.started_at = datetime.now(timezone.utc)
        record.add_log("Starting planning phase...")

        try:
            # Map chat mode to AgentMode
            if record.mode == "integrated":
                agent_mode = AgentMode.HYBRID
            elif record.mode in ("registry", "offline"):
                agent_mode = AgentMode.REGISTRY
            else:
                agent_mode = AgentMode.AUTONOMOUS

            core = AgentCore(mode=agent_mode)
            await core.initialize()

            record.status = SubagentStatus.RUNNING
            record.current_step = "Executing goal"
            record.add_log("Executing plan...")

            goal_obj = AgentGoal(description=record.goal)
            result = await core.execute_goal(goal_obj)

            record.duration_secs = record.elapsed
            record.completed_at = datetime.now(timezone.utc)

            if result.plan:
                for idx, s in enumerate(result.plan.steps):
                    task_res = getattr(s, "result", {}) or {}
                    out_text = (
                        task_res.get("output", "") if isinstance(task_res, dict) else str(task_res)
                    )
                    err_text = task_res.get("error", "") if isinstance(task_res, dict) else ""
                    st_val = (
                        task_res.get("status", "completed")
                        if isinstance(task_res, dict)
                        else "completed"
                    )
                    task = SubagentTask(
                        id=f"step_{idx + 1}",
                        description=getattr(s, "description", f"Step {idx + 1}"),
                        tool=getattr(s, "tool", ""),
                        command=getattr(s, "command", ""),
                        status=st_val,
                        output=out_text,
                        error=err_text,
                    )
                    record.add_task(task)

            # Collect findings
            if result.findings:
                for f in result.findings:
                    record.add_finding(f)

            if result.success:
                record.status = SubagentStatus.COMPLETED
                record.progress = 1.0
                record.summary = result.summary or "Subagent completed goal successfully."
                record.add_log("Goal execution completed successfully.")
            else:
                record.status = SubagentStatus.FAILED
                record.summary = result.summary or "Subagent execution ended with errors."
                record.add_log(f"Subagent goal execution failed: {result.summary}")

            # Merge findings into main chat session context if provided
            if chat_session is not None and hasattr(chat_session, "context") and result.findings:
                existing = chat_session.context.setdefault("findings", [])
                existing.extend(result.findings)

            await core.shutdown()

        except asyncio.CancelledError:
            record.status = SubagentStatus.CANCELLED
            record.completed_at = datetime.now(timezone.utc)
            record.add_log("Execution cancelled.")
            raise
        except Exception as exc:
            logger.error("Error executing subagent %s: %s", record.id, exc, exc_info=True)
            record.status = SubagentStatus.FAILED
            record.error = str(exc)
            record.completed_at = datetime.now(timezone.utc)
            record.add_log(f"Fatal error: {exc}")

        return record

    def render_table(self) -> Table:
        """Generate a Rich Table listing all subagents with status and metrics."""
        table = Table(
            title="Siyarix Subagent Fleet",
            header_style="bold cyan",
            border_style="cyan",
            box=ROUNDED,
            expand=True,
        )
        table.add_column("Agent ID", style="bold white", no_wrap=True)
        table.add_column("Role", style="magenta")
        table.add_column("Status", style="bold")
        table.add_column("Current Step / Progress", style="white")
        table.add_column("Findings", justify="center", style="yellow")
        table.add_column("Duration", justify="right", style="cyan")
        table.add_column("Goal", style="dim white")

        status_colors = {
            SubagentStatus.RUNNING: "bold green",
            SubagentStatus.PLANNING: "bold yellow",
            SubagentStatus.COMPLETED: "bold cyan",
            SubagentStatus.FAILED: "bold red",
            SubagentStatus.CANCELLED: "bold bright_black",
            SubagentStatus.IDLE: "dim white",
        }

        for rec in self.list_subagents():
            is_active = rec.id == self._active_id
            active_prefix = "[bold #00ffcc]★ [/bold #00ffcc]" if is_active else "  "
            id_styled = f"{active_prefix}{rec.id}"
            st_style = status_colors.get(rec.status, "white")
            status_badge = f"[{st_style}]{rec.status.value.upper()}[/{st_style}]"

            step_desc = (rec.current_step or "Idle")[:30]
            if rec.status == SubagentStatus.RUNNING:
                pct = int(rec.progress * 100)
                progress_str = f"{step_desc} ({pct}%)"
            else:
                progress_str = step_desc

            findings_badge = (
                f"[bold yellow]{len(rec.findings)}[/bold yellow]"
                if rec.findings
                else "[dim]0[/dim]"
            )
            dur_str = f"{rec.elapsed:.1f}s"
            goal_short = rec.goal[:45] + ("..." if len(rec.goal) > 45 else "")

            table.add_row(
                id_styled,
                rec.role.value if isinstance(rec.role, SubagentRole) else str(rec.role),
                status_badge,
                progress_str,
                findings_badge,
                dur_str,
                goal_short,
            )

        return table

    def render_preview(self, agent_id: str | None = None) -> Panel:
        """Render a comprehensive execution preview panel for the specified or active subagent."""
        target_id = agent_id or self._active_id
        rec = self.get(target_id) if target_id else None

        if not rec:
            return Panel(
                "[dim]No active subagent. Use '/agent run <goal>' or '/agent spawn <role> <goal>' to start one.[/dim]",
                title="[bold cyan]Subagent Preview[/bold cyan]",
                border_style="dim",
                box=ROUNDED,
            )

        status_colors = {
            SubagentStatus.RUNNING: "green",
            SubagentStatus.PLANNING: "yellow",
            SubagentStatus.COMPLETED: "cyan",
            SubagentStatus.FAILED: "red",
            SubagentStatus.CANCELLED: "bright_black",
            SubagentStatus.IDLE: "dim",
        }
        accent = status_colors.get(rec.status, "cyan")

        content = Text()
        # Header Info
        content.append("ID: ", style="bold #00ffcc")
        content.append(f"{rec.id}  ", style="bold white")
        content.append("Role: ", style="bold #ff00ff")
        role_str = rec.role.value if isinstance(rec.role, SubagentRole) else str(rec.role)
        content.append(f"{role_str}  ", style="white")
        content.append("Status: ", style=f"bold {accent}")
        content.append(f"{rec.status.value.upper()}  ", style=f"bold {accent}")
        content.append("Duration: ", style="dim")
        content.append(f"{rec.elapsed:.1f}s\n", style="white")

        content.append("Goal: ", style="bold yellow")
        content.append(f"{rec.goal}\n\n", style="white")

        # Step trace
        content.append("── Execution Steps ──\n", style="bold cyan")
        if rec.tasks:
            for t in rec.tasks[-6:]:
                icon = "✓" if t.status == "completed" else ("✗" if t.status == "failed" else "▶")
                c_icon = (
                    "green"
                    if t.status == "completed"
                    else ("red" if t.status == "failed" else "yellow")
                )
                tool_label = f"[{t.tool}] " if t.tool else ""
                content.append(
                    f"  [{c_icon}]{icon}[/{c_icon}] {tool_label}{t.description}\n", style="white"
                )
                if t.output:
                    snippet = t.output.strip().split("\n")[0][:70]
                    content.append(f"      [dim]Output: {snippet}[/dim]\n")
        else:
            content.append(f"  • {rec.current_step}\n", style="dim")

        # Findings preview
        if rec.findings:
            content.append("\n── Findings Discovered ──\n", style="bold yellow")
            for f in rec.findings[:5]:
                sev = f.get("severity", "info").upper()
                title = f.get("title", f.get("type", "Finding"))
                content.append(f"  [red]• [{sev}][/red] {title}\n", style="white")
            if len(rec.findings) > 5:
                content.append(f"  [dim]... and {len(rec.findings) - 5} more[/dim]\n")

        # Logs tail
        if rec.logs:
            content.append("\n── Live Log Tail ──\n", style="bold bright_black")
            for line in rec.logs[-4:]:
                content.append(f"  {line}\n", style="dim")

        if rec.summary:
            content.append("\n── Summary ──\n", style="bold green")
            content.append(f"{rec.summary}\n", style="white")

        return Panel(
            content,
            title=f"[bold {accent}]Subagent Preview: {rec.id}[/bold {accent}]",
            border_style=accent,
            padding=(1, 2),
            box=ROUNDED,
        )


__all__ = [
    "SubagentRole",
    "SubagentStatus",
    "SubagentTask",
    "SubagentRecord",
    "SubagentManager",
]
