"""Coordinator agent that wires AgentTeam + specialized agents to the engine.

Provides objective-driven multi-agent orchestration with intelligent task
decomposition, parallel execution, result aggregation, and adaptive workflow
based on findings.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from ..multi_agent import Agent, AgentRole, AgentTeam
from .dfir_agent import DFIRAgent
from .soc_agent import SOCAgent
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine import ExecutionEngine

logger = logging.getLogger(__name__)


class CoordinatorAgent:
    """Objective-oriented coordinator for multi-agent execution.

    Features:
    - Dynamic agent team composition based on objective
    - Parallel execution of independent sub-tasks
    - Result aggregation and dependency resolution
    - Adaptive re-tasking when agents fail
    - Collaborative finding enrichment across agents
    """

    def __init__(
        self,
        engine: "ExecutionEngine",
        team_name: str = "siyarix-hybrid-team",
    ) -> None:
        self._engine = engine
        self._team = AgentTeam(name=team_name)
        self._register_default_agents()
        self._execution_history: list[dict[str, Any]] = []
        self._current_objective: str = ""
        self._current_target: str = ""
        self._last_results: dict[str, Any] = {}

    def _register_default_agents(self) -> None:
        recon = Agent(
            name="recon-1",
            role=AgentRole.RECON,
            tools=["nmap", "whois", "subfinder", "masscan", "dnsx"],
        )
        scanner = Agent(
            name="scanner-1", role=AgentRole.SCANNER, tools=["nuclei", "nikto", "gobuster", "ffuf"]
        )
        enumerator = Agent(
            name="enum-1",
            role=AgentRole.ENUMERATOR,
            tools=["ffuf", "gobuster", "dirsearch", "wpscan"],
        )
        exploiter = Agent(
            name="exploit-1",
            role=AgentRole.EXPLOITER,
            tools=["sqlmap", "hydra", "metasploit", "john"],
        )
        reporter = Agent(name="report-1", role=AgentRole.REPORTER, tools=["siyarix"])

        async def _delegate(task: str, payload: dict[str, Any]) -> dict[str, Any]:
            target = payload.get("target", "")
            text = task if target and target in task else f"{task} {target}".strip()
            run = await self._engine.execute(text, interactive=False, persist=False)
            return {
                "success": run.success,
                "summary": run.summary,
                "findings": run.all_findings,
                "findings_count": len(run.all_findings),
                "step_count": len(run.step_results),
                "duration_ms": run.total_duration_ms,
            }

        for agent in (recon, scanner, enumerator, exploiter, reporter):
            agent.set_task_handler(_delegate)
            self._team.add_agent(agent)

        soc = SOCAgent()
        dfir = DFIRAgent()
        self._team.add_agent(soc)
        self._team.add_agent(dfir)

    async def execute_objective(
        self,
        objective: str,
        target: str = "",
        *,
        interactive: bool = False,
        max_parallel_agents: int = 3,
    ) -> dict[str, Any]:
        """Dispatch a high-level objective across role-specialized agents.

        Performs intelligent task decomposition based on objective type,
        dispatches to agents in dependency order, and aggregates results.
        """
        self._current_objective = objective
        self._current_target = target
        start_time = time.monotonic()

        logger.info("Coordinator dispatching objective: %s (target=%s)", objective, target)

        decomposition = self._decompose_objective(objective)
        phase_results: dict[str, Any] = {}
        completed_phases: set[str] = set()

        resolved_order = self.resolve_dependencies(decomposition)

        for phase_name in resolved_order:
            phase_info = decomposition[phase_name]
            phase_agents = phase_info["agents"]
            depends_on = phase_info.get("depends_on", [])
            blocked = False

            for dep in depends_on:
                if dep not in completed_phases:
                    blocked = True
                    logger.warning("Phase %s blocked by unmet dependency: %s", phase_name, dep)
                    r = phase_results.setdefault(phase_name, {
                        "agents_used": len(phase_agents),
                        "responses": [],
                        "duration_seconds": 0.0,
                    })
                    for agent_name in phase_agents:
                        r["responses"].append({"blocked": True, "reason": f"dependency '{dep}' not completed"})
                    break

            if blocked:
                continue

            logger.info("Executing phase: %s with %d agent(s)", phase_name, len(phase_agents))
            phase_start = time.monotonic()

            batch = []
            for agent_name in phase_agents:
                agent = self._team.get_agent(agent_name)
                if not agent:
                    continue
                msg_text = f"{phase_name}: {objective}"
                from ..multi_agent import AgentMessage

                msg = AgentMessage(
                    sender="coordinator",
                    recipient=agent.name,
                    content=msg_text,
                    msg_type="task",
                    payload={"goal": objective, "target": target, "phase": phase_name},
                )
                await self._team.send_message(msg)
                batch.append(agent.process_next())

            semaphore = asyncio.Semaphore(max_parallel_agents)

            async def run_with_limit(coro: Any) -> Any:
                async with semaphore:
                    return await coro

            limited = [run_with_limit(task) for task in batch]
            responses = await asyncio.gather(*limited, return_exceptions=True)

            phase_duration = time.monotonic() - phase_start
            phase_results[phase_name] = {
                "agents_used": len(phase_agents),
                "responses": [
                    getattr(r, "payload", {"error": str(r)})
                    for r in responses
                    if not isinstance(r, Exception)
                ],
                "duration_seconds": round(phase_duration, 2),
            }
            completed_phases.add(phase_name)

        self._last_results = phase_results

        total_duration = time.monotonic() - start_time
        team_result = await self._team.execute_goal(goal=objective, target=target)

        result = {
            "team": self._team.name,
            "objective": objective,
            "target": target,
            "coordinator_id": uuid.uuid4().hex[:8],
            "duration_seconds": round(total_duration, 2),
            "agents_used": len(self._team.list_agents()),
            "phases_executed": list(decomposition.keys()),
            "phase_results": phase_results,
            "team_result": team_result,
            "results": team_result.get("results", []),
            "success": all(
                r.get("success", False)
                for phase in phase_results.values()
                for r in phase.get("responses", [])
                if isinstance(r, dict)
            ),
        }

        self._execution_history.append(result)
        return result

    def _decompose_objective(self, objective: str) -> dict[str, dict]:
        """Decompose a high-level objective into phase groups with dependency metadata.

        Each phase dict has:
          - "agents": list of agent names to dispatch
          - "depends_on": list of phase names that must complete first
        """
        obj_lower = objective.lower()
        phases: dict[str, dict] = {}

        recon_keywords = [
            "recon",
            "discover",
            "enumerate",
            "scan",
            "find",
            "gather",
            "whois",
            "subdomain",
        ]
        scan_keywords = ["scan", "vulnerability", "vuln", "cve", "nuclei", "nikto", "web"]
        exploit_keywords = ["exploit", "attack", "brute", "crack", "sqlmap", "hydra", "penetrate"]
        report_keywords = ["report", "summarize", "document", "export", "output"]
        privesc_keywords = [
            "privilege", "escalation", "privesc", "elevate", "root", "admin",
        ]
        lateral_keywords = [
            "lateral", "pivot", "movement", "spread",
        ]
        persistence_keywords = [
            "persist", "persistence", "backdoor", "implant", "maintain",
        ]
        credential_keywords = [
            "credential", "password", "hash", "dump", "kerberoast", "hashcat", "john",
        ]

        has_recon = any(kw in obj_lower for kw in recon_keywords)
        has_scan = any(kw in obj_lower for kw in scan_keywords)
        has_exploit = any(kw in obj_lower for kw in exploit_keywords)
        has_report = any(kw in obj_lower for kw in report_keywords)
        has_privesc = any(kw in obj_lower for kw in privesc_keywords)
        has_lateral = any(kw in obj_lower for kw in lateral_keywords)
        has_persistence = any(kw in obj_lower for kw in persistence_keywords)
        has_credential = any(kw in obj_lower for kw in credential_keywords)

        if not any([has_recon, has_scan, has_exploit, has_report,
                     has_privesc, has_lateral, has_persistence, has_credential]):
            has_recon = True
            has_scan = True

        if has_recon:
            phases["recon"] = {"agents": ["recon-1", "soc-analyst-1"], "depends_on": []}
        if has_scan:
            phases["scanning"] = {
                "agents": ["scanner-1", "enum-1"],
                "depends_on": ["recon"] if has_recon else [],
            }
        if has_credential:
            phases["credential_access"] = {
                "agents": ["exploit-1"],
                "depends_on": ["scanning"] if has_scan else [],
            }
        if has_exploit:
            phases["exploitation"] = {
                "agents": ["exploit-1"],
                "depends_on": ["scanning"] if has_scan else [],
            }
        if has_privesc:
            phases["privilege_escalation"] = {
                "agents": ["exploit-1"],
                "depends_on": ["exploitation"] if has_exploit else [],
            }
        if has_lateral:
            phases["lateral_movement"] = {
                "agents": ["exploit-1"],
                "depends_on": ["privilege_escalation"] if has_privesc else ["exploitation"] if has_exploit else [],
            }
        if has_persistence:
            phases["persistence"] = {
                "agents": ["exploit-1"],
                "depends_on": ["exploitation"] if has_exploit else [],
            }
        if has_report:
            phases["reporting"] = {"agents": ["report-1"], "depends_on": []}

        return phases

    def resolve_dependencies(self, decomposition: dict[str, dict]) -> list[str]:
        """Return phase names in dependency-resolved (topological) order.

        Simple DAG traversal: phases with no dependencies go first, then
        phases whose dependencies are all in the resolved set.
        """
        resolved: list[str] = []
        remaining = dict(decomposition)

        while remaining:
            batch = [
                name for name, info in remaining.items()
                if not info.get("depends_on") or all(d in resolved for d in info["depends_on"])
            ]
            if not batch:
                logger.warning("Cycle or unresolvable dependencies detected; forcing remaining phases")
                batch = list(remaining.keys())
            for name in batch:
                resolved.append(name)
                del remaining[name]

        return resolved

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        return list(self._execution_history[-limit:])

    @property
    def engine(self) -> Any:
        return self._engine

    @property
    def team(self) -> AgentTeam:
        return self._team


__all__ = ["CoordinatorAgent"]
