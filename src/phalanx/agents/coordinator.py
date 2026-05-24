"""Coordinator agent that wires AgentTeam + specialized agents to the engine."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from ..multi_agent import Agent, AgentRole, AgentTeam
from .dfir_agent import DFIRAgent
from .soc_agent import SOCAgent

if TYPE_CHECKING:
    from ..engine import ExecutionEngine


class CoordinatorAgent:
    """Objective-oriented coordinator for multi-agent execution."""

    def __init__(self, engine: "ExecutionEngine") -> None:
        self._engine = engine
        self._team = AgentTeam(name="siyarix-hybrid-team")
        self._register_default_agents()

    def _register_default_agents(self) -> None:
        recon = Agent(name="recon-1", role=AgentRole.RECON, tools=["nmap", "whois", "subfinder"])
        scanner = Agent(name="scanner-1", role=AgentRole.SCANNER, tools=["nuclei", "nikto", "gobuster"])
        enumerator = Agent(name="enum-1", role=AgentRole.ENUMERATOR, tools=["ffuf", "gobuster"])
        exploiter = Agent(name="exploit-1", role=AgentRole.EXPLOITER, tools=["sqlmap", "hydra"])
        reporter = Agent(name="report-1", role=AgentRole.REPORTER, tools=["siyarix"])
        soc = SOCAgent()
        dfir = DFIRAgent()

        async def _delegate(task: str, payload: dict[str, Any]) -> dict[str, Any]:
            target = payload.get("target", "")
            text = task if target and target in task else f"{task} {target}".strip()
            run = await self._engine.execute(text, interactive=False, persist=False)
            return {
                "success": run.success,
                "summary": run.summary,
                "findings": len(run.all_findings),
                "step_count": len(run.step_results),
            }

        for agent in (recon, scanner, enumerator, exploiter, reporter):
            agent.set_task_handler(_delegate)
            self._team.add_agent(agent)
        self._team.add_agent(soc)
        self._team.add_agent(dfir)

    async def execute_objective(
        self,
        objective: str,
        target: str = "",
        *,
        interactive: bool = False,  # noqa: ARG002
    ) -> dict[str, Any]:
        """Dispatch a high-level objective across role-specialized agents."""
        return await self._team.execute_goal(goal=objective, target=target)
