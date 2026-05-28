# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Agent lifecycle commands for managing sub-agents in runtime.
Provides spawn/list/kill functionality.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class AgentInstance:
    id: str
    name: str
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "idle"  # idle | running | completed | failed
    task: str = ""


class AgentLifecycle:
    def __init__(self) -> None:
        self._agents: dict[str, AgentInstance] = {}

    def spawn(self, name: str, task: str = "") -> AgentInstance:
        agent_id = str(uuid.uuid4())[:8]
        instance = AgentInstance(id=agent_id, name=name, task=task, status="running")
        self._agents[agent_id] = instance
        logger.info("Spawned agent %s (%s)", name, agent_id)
        return instance

    def list_agents(self) -> list[AgentInstance]:
        return list(self._agents.values())

    def kill(self, agent_id: str) -> bool:
        if agent_id in self._agents:
            self._agents[agent_id].status = "completed"
            logger.info("Killed agent %s", agent_id)
            return True
        return False

    def get(self, agent_id: str) -> AgentInstance | None:
        return self._agents.get(agent_id)

    def show_table(self) -> None:
        agents = self.list_agents()
        if not agents:
            console.print("[dim]No active agents.[/dim]")
            return
        table = Table(title=f"Active Agents ({len(agents)})", header_style="bold cyan")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Task", style="white")
        for a in agents:
            table.add_row(a.id, a.name, a.status, a.task[:40])
        console.print(table)


__all__ = ["AgentLifecycle", "AgentInstance"]
