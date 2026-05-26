"""Phalanx Multi-Agent Framework — Collaborative autonomous agent system.

Provides:
  • **Agent** — Individual autonomous agent with role, tools, and memory
  • **AgentTeam** — Coordinate multiple agents working toward a shared goal
  • **AgentMessage** — Inter-agent communication protocol

Architecture:
  Agents communicate via message passing. Each agent has a role (recon, scanner,
  exploiter, reporter) and can delegate subtasks to other agents. The AgentTeam
  orchestrates the workflow and aggregates results.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Awaitable, Callable

__all__ = [
    "Agent",
    "AgentTeam",
    "AgentMessage",
    "AgentRole",
    "AgentStatus",
]

logger = logging.getLogger(__name__)


class AgentRole(StrEnum):
    """Predefined agent roles in a cybersecurity operation."""

    RECON = "recon"
    SCANNER = "scanner"
    ENUMERATOR = "enumerator"
    EXPLOITER = "exploiter"
    REPORTER = "reporter"
    COORDINATOR = "coordinator"
    CUSTOM = "custom"
    SOC = "soc"
    DFIR = "dfir"


class AgentStatus(StrEnum):
    """Agent lifecycle status."""

    IDLE = "idle"
    WORKING = "working"
    WAITING = "waiting"
    DONE = "done"
    FAILED = "failed"


@dataclass
class AgentMessage:
    """Inter-agent communication message."""

    sender: str
    recipient: str
    content: str
    msg_type: str = "task"  # task | result | query | broadcast
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class AgentMemory:
    """Agent's working memory — tracks findings, commands, and context."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    commands_run: list[str] = field(default_factory=list)
    messages_received: deque[AgentMessage] = field(
        default_factory=lambda: deque(maxlen=100)
    )
    messages_sent: deque[AgentMessage] = field(
        default_factory=lambda: deque(maxlen=100)
    )
    context: dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)

    def add_command(self, command: str) -> None:
        self.commands_run.append(command)

    def summary(self) -> dict[str, Any]:
        return {
            "findings_count": len(self.findings),
            "commands_run": len(self.commands_run),
            "messages_in": len(self.messages_received),
            "messages_out": len(self.messages_sent),
        }


class Agent:
    """An individual autonomous agent with a specific role.

    Each agent can:
    - Execute tasks using the ExecutionEngine
    - Send/receive messages to/from other agents
    - Maintain its own memory of findings and context
    - Delegate subtasks to other agents via the team coordinator
    """

    def __init__(
        self,
        name: str,
        role: AgentRole,
        tools: list[str] | None = None,
        description: str = "",
    ) -> None:
        self.agent_id = str(uuid.uuid4())[:8]
        self.name = name
        self.role = role
        self.tools = tools or []
        self.description = description or f"{role.value} agent"
        self.status = AgentStatus.IDLE
        self.memory = AgentMemory()
        self._inbox: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._task_handler: (
            Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]] | None
        ) = None

    def set_task_handler(
        self,
        handler: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
    ) -> None:
        """Set the async function that handles task execution."""
        self._task_handler = handler

    async def receive(self, message: AgentMessage) -> None:
        """Receive a message from another agent or the coordinator."""
        self.memory.messages_received.append(message)
        await self._inbox.put(message)
        logger.debug(
            "Agent %s received message from %s: %s",
            self.name,
            message.sender,
            message.msg_type,
        )

    async def process_next(self) -> AgentMessage | None:
        """Process the next message in the inbox.

        Returns a response message, or None if inbox is empty.
        """
        try:
            msg = self._inbox.get_nowait()
        except asyncio.QueueEmpty:
            return None

        self.status = AgentStatus.WORKING
        logger.info("Agent %s processing: %s", self.name, msg.content[:100])

        response_payload: dict[str, Any] = {}

        if msg.msg_type == "task" and self._task_handler:
            try:
                result = await self._task_handler(msg.content, msg.payload)
                response_payload = result
                self.status = AgentStatus.DONE
            except Exception as exc:
                logger.error("Agent %s task failed: %s", self.name, exc)
                response_payload = {"error": str(exc)}
                self.status = AgentStatus.FAILED
        elif msg.msg_type == "query":
            response_payload = {"memory_summary": self.memory.summary()}
            self.status = AgentStatus.IDLE
        else:
            response_payload = {"acknowledged": True}
            self.status = AgentStatus.IDLE

        response = AgentMessage(
            sender=self.name,
            recipient=msg.sender,
            content=f"Response from {self.name}",
            msg_type="result",
            payload=response_payload,
        )
        self.memory.messages_sent.append(response)
        return response

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role.value,
            "status": self.status.value,
            "tools": self.tools,
            "description": self.description,
            "memory": self.memory.summary(),
        }


class AgentTeam:
    """Coordinate multiple agents working toward a shared goal.

    The team manages:
    - Agent lifecycle (spawn, assign, retire)
    - Message routing between agents
    - Task decomposition and delegation
    - Result aggregation

    Usage::

        team = AgentTeam("PenTest Alpha")
        team.add_agent(Agent("recon-1", AgentRole.RECON, tools=["nmap", "whois"]))
        team.add_agent(Agent("scanner-1", AgentRole.SCANNER, tools=["nuclei", "nikto"]))
        results = await team.execute_goal("Full pentest of target.com")
    """

    def __init__(self, name: str = "default-team") -> None:
        self.team_id = str(uuid.uuid4())[:8]
        self.name = name
        self._agents: dict[str, Agent] = {}
        self._message_log: deque[AgentMessage] = deque(maxlen=500)
        self._results: list[dict[str, Any]] = []

    def add_agent(self, agent: Agent) -> None:
        """Register an agent with the team."""
        self._agents[agent.name] = agent
        logger.info(
            "Agent '%s' (%s) joined team '%s'", agent.name, agent.role.value, self.name
        )

    def remove_agent(self, name: str) -> bool:
        """Remove an agent from the team."""
        if name in self._agents:
            del self._agents[name]
            return True
        return False

    def get_agent(self, name: str) -> Agent | None:
        return self._agents.get(name)

    def agents_by_role(self, role: AgentRole) -> list[Agent]:
        """Get all agents with a specific role."""
        return [a for a in self._agents.values() if a.role == role]

    def list_agents(self) -> list[Agent]:
        """List all agents and their status."""
        return list(self._agents.values())

    async def send_message(self, message: AgentMessage) -> None:
        """Route a message to the recipient agent."""
        self._message_log.append(message)
        recipient = self._agents.get(message.recipient)
        if recipient:
            await recipient.receive(message)
        else:
            logger.warning("Message to unknown agent: %s", message.recipient)

    async def broadcast(
        self, sender: str, content: str, payload: dict[str, Any] | None = None
    ) -> None:
        """Broadcast a message to all agents."""
        for agent_name in self._agents:
            if agent_name != sender:
                msg = AgentMessage(
                    sender=sender,
                    recipient=agent_name,
                    content=content,
                    msg_type="broadcast",
                    payload=payload or {},
                )
                await self.send_message(msg)

    async def execute_goal(self, goal: str, target: str = "") -> dict[str, Any]:
        """Decompose a goal and delegate to appropriate agents.

        This is a simple round-robin delegation for now.
        Phase 3 will add intelligent task decomposition.
        """
        results: list[dict[str, Any]] = []

        # Assign the goal to all agents in role order
        role_order = [
            AgentRole.RECON,
            AgentRole.SCANNER,
            AgentRole.ENUMERATOR,
            AgentRole.EXPLOITER,
            AgentRole.REPORTER,
        ]

        for role in role_order:
            agents = self.agents_by_role(role)
            if not agents:
                continue

            # Send task to all agents of this role in parallel
            tasks = []
            for agent in agents:
                msg = AgentMessage(
                    sender="coordinator",
                    recipient=agent.name,
                    content=f"{role.value}: {goal}",
                    msg_type="task",
                    payload={"goal": goal, "target": target, "role": role.value},
                )
                await self.send_message(msg)
                tasks.append(agent.process_next())

            # Await all responses
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for resp in responses:
                if isinstance(resp, AgentMessage):
                    results.append(resp.payload)
                elif isinstance(resp, Exception):
                    results.append({"error": str(resp)})

        self._results = results
        return {
            "team": self.name,
            "goal": goal,
            "target": target,
            "agents_used": len(self._agents),
            "results": results,
        }

    def summary(self) -> dict[str, Any]:
        return {
            "team_id": self.team_id,
            "name": self.name,
            "agent_count": len(self._agents),
            "agents": [a.to_dict() for a in self._agents.values()],
            "messages_total": len(self._message_log),
            "results_count": len(self._results),
        }
