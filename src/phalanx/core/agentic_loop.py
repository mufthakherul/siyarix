"""Agentic Loop — Goal-driven autonomous execution loop with reflection."""

from __future__ import annotations

import logging
# Use TYPE_CHECKING to avoid circular import
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from siyarix.engine import EngineResult, ExecutionEngine

logger = logging.getLogger(__name__)
console = Console()


class AgenticLoop:
    """Goal-driven autonomous execution loop with reflective heuristics.

    Implements the observe → reason → act cycle:
    1. **Observe** — Collect context: current findings, target state, tool output
    2. **Reflect** — Hardcoded tactical reflection (e.g., if port 22 open -> run hydra)
    3. **Reason** — Ask the AI planner to decide next action based on observations
    4. **Act** — Execute the planned step(s)
    5. **Evaluate** — Check if the goal is achieved or if re-planning is needed
    """

    def __init__(
        self,
        engine: "ExecutionEngine",
        goal: str,
        target: str = "",
        max_iterations: int = 10,
        interactive: bool = True,
    ) -> None:
        self._engine = engine
        self._goal = goal
        self._target = target
        self._max_iterations = max_iterations
        self._interactive = interactive
        self._observations: list[dict[str, Any]] = []
        self._iteration = 0
        self._all_findings: list[dict[str, Any]] = []
        self._completed = False
        self._reflection_queue: list[str] = []

    async def run(self) -> dict[str, Any]:
        """Execute the agentic loop until goal completion or max iterations."""
        console.print(
            Panel(
                f"[bold]Goal:[/bold] {self._goal}\n"
                f"[bold]Target:[/bold] {self._target or 'auto-detect'}\n"
                f"[bold]Max iterations:[/bold] {self._max_iterations}",
                title="[bold bright_cyan]🤖 Reflective Agentic Loop — Starting[/bold bright_cyan]",
                border_style="cyan",
            )
        )

        while self._iteration < self._max_iterations and not self._completed:
            self._iteration += 1
            console.print(
                f"\n[bold cyan]━━━ Iteration {self._iteration}/{self._max_iterations} ━━━[/bold cyan]"
            )

            # 1. OBSERVE — build context from accumulated findings
            context = self._observe()

            # 2. REFLECT — check if there are immediate tactical follow-ups
            self._reflect()

            # 3. REASON — ask the engine to plan next actions or use reflection queue
            if self._reflection_queue:
                instruction = self._reflection_queue.pop(0)
                console.print(
                    f"[dim]🧠 Tactical Reflection Triggered: {instruction}[/dim]"
                )
            else:
                console.print(
                    "[dim]🔍 Observing context and reasoning next steps...[/dim]"
                )
                instruction = self._reason(context) or ""

            if instruction.lower().strip() in (
                "done",
                "complete",
                "finished",
            ):
                self._completed = True
                console.print(
                    "[bold green]✅ Goal achieved — loop complete[/bold green]"
                )
                break

            # 4. ACT — execute the plan
            console.print(f"[dim]⚡ Acting: {instruction[:100]}...[/dim]")
            try:
                result = await self._engine.execute(
                    instruction,
                    interactive=self._interactive,
                )

                # 5. EVALUATE — collect findings and check progress
                self._evaluate(result)

            except Exception as exc:
                logger.error(
                    "Agentic loop iteration %d failed: %s", self._iteration, exc
                )
                self._observations.append(
                    {
                        "iteration": self._iteration,
                        "error": str(exc),
                        "phase": "act",
                    }
                )
                if self._interactive:
                    console.print(
                        f"[red]Error in iteration {self._iteration}: {exc}[/red]"
                    )

        summary = {
            "goal": self._goal,
            "target": self._target,
            "iterations": self._iteration,
            "completed": self._completed,
            "total_findings": len(self._all_findings),
            "observations": self._observations[-5:],
        }

        console.print(
            Panel(
                f"[bold]Iterations:[/bold] {self._iteration}\n"
                f"[bold]Completed:[/bold] {'Yes' if self._completed else 'No (max iterations reached)'}\n"
                f"[bold]Findings:[/bold] {len(self._all_findings)}",
                title="[bold bright_cyan]🤖 Agentic Loop — Summary[/bold bright_cyan]",
                border_style="green" if self._completed else "yellow",
            )
        )

        return summary

    def _observe(self) -> dict[str, Any]:
        """Phase 1: Collect current state and observations."""
        return {
            "goal": self._goal,
            "target": self._target,
            "iteration": self._iteration,
            "findings_so_far": len(self._all_findings),
            "recent_observations": self._observations[-3:],
            "recent_findings": self._all_findings[-5:] if self._all_findings else [],
        }

    def _reflect(self) -> None:
        """Phase 2: Live Graph-driven tactical reflection.
        Queries the KnowledgeGraph to traverse hosts, ports, services,
        subdomains, and vulnerabilities, then queues targeted follow-up actions.
        """
        from siyarix.knowledge_graph import EdgeType, NodeType

        graph = self._engine.graph

        # 1. Traverse all HOST nodes
        hosts = graph.find_nodes(NodeType.HOST)
        for host in hosts:
            host_label = host.label

            # Find all port edges for this host
            port_edges = graph.get_edges(
                source_id=host.node_id, edge_type=EdgeType.HAS_PORT
            )
            for port_edge in port_edges:
                port_node = graph.get_node(port_edge.target_id)
                if not port_node:
                    continue

                port_val = port_node.properties.get("port")

                # Find all services running on this port
                svc_edges = graph.get_edges(
                    source_id=port_node.node_id, edge_type=EdgeType.RUNS_SERVICE
                )
                for svc_edge in svc_edges:
                    svc_node = graph.get_node(svc_edge.target_id)
                    if not svc_node:
                        continue

                    svc_name = svc_node.label.lower()

                    # Heuristic A: Weak auth services (SSH, FTP, Telnet) -> Hydra Brute Force
                    if svc_name in ("ssh", "ftp", "telnet"):
                        action = f"run hydra brute force on {host_label} {svc_name} using common credentials"
                        if action not in self._reflection_queue:
                            self._reflection_queue.append(action)

                    # Heuristic B: HTTP / HTTPS services -> Nuclei scanner + directory enum
                    elif (
                        svc_name in ("http", "https")
                        or "http" in svc_name
                        or port_val in (80, 443, 8080, 8443)
                    ):
                        action = f"run nuclei vulnerability scan against {host_label}"
                        if action not in self._reflection_queue:
                            self._reflection_queue.append(action)

                        # Add a directory enumeration follow-up if not already queued
                        dir_action = f"run gobuster directory scan on {host_label}"
                        if dir_action not in self._reflection_queue:
                            self._reflection_queue.append(dir_action)

        # 2. Traverse all SUBDOMAIN nodes
        subdomains = graph.find_nodes(NodeType.SUBDOMAIN)
        for sub in subdomains:
            action = f"run fast port scan on {sub.label}"
            if action not in self._reflection_queue:
                self._reflection_queue.append(action)

        # 3. Traverse all VULNERABILITY nodes for deep exploits / validation
        vulns = graph.find_nodes(NodeType.VULNERABILITY)
        for vuln in vulns:
            severity = vuln.properties.get("severity", "info").lower()
            if severity in ("critical", "high"):
                action = f"verify vulnerability {vuln.label} on {self._target}"
                if action not in self._reflection_queue:
                    self._reflection_queue.append(action)

    def _reason(self, context: dict[str, Any]) -> str | None:
        """Phase 3: Determine next action using AI planner."""
        if self._iteration == 1:
            return f"{self._goal}" + (f" on {self._target}" if self._target else "")

        findings_summary = ""
        if self._all_findings:
            findings_summary = f"\n\nFindings so far ({len(self._all_findings)}):\n"
            for f in self._all_findings[-3:]:
                findings_summary += f"  - [{f.get('severity', 'info')}] {f.get('description', str(f))[:100]}\n"

        prev_errors = [o.get("error", "") for o in self._observations if o.get("error")]
        error_context = ""
        if prev_errors:
            error_context = "\n\nPrevious errors to avoid:\n  " + "\n  ".join(
                prev_errors[-2:]
            )

        return (
            f"Continue working on the goal: {self._goal}"
            + (f" targeting {self._target}" if self._target else "")
            + f"\nThis is iteration {self._iteration} of {self._max_iterations}."
            + findings_summary
            + error_context
            + "\nWhat should be the next step? If the goal is fully achieved, respond with 'done'."
        )

    def _evaluate(self, result: "EngineResult") -> None:
        """Phase 5: Evaluate results and update observations."""
        observation = {
            "iteration": self._iteration,
            "success": result.success,
            "steps_run": len(result.step_results),
            "findings_count": len(result.all_findings),
            "duration_ms": result.total_duration_ms,
        }
        self._observations.append(observation)
        self._all_findings.extend(result.all_findings)

        if not result.success and self._iteration >= 3:
            recent_failures = sum(
                1 for o in self._observations[-3:] if not o.get("success", True)
            )
            if recent_failures >= 3:
                logger.warning("3 consecutive failures — stopping agentic loop")
                self._completed = True
