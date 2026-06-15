# SPDX-License-Identifier: AGPL-3.0-or-later
"""Core agent system with goal decomposition, execution, and self-reflection."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..registry import ToolRegistry
from ..planner import Planner, ExecutionPlan, PlanStatus, StepStatus, PlanStep
from ..executor import Executor
from ..validators import Validator, RecoveryAction
from ..context import ContextManager
from ..memory import MemoryManager
from ..providers import ProviderManager
from ..providers.usage import UsageTracker
from ..workflow import WorkflowEngine
from ..events import Event, EventType, get_event_bus
from ..exceptions import BudgetExceededError
from ..knowledge_graph import KnowledgeGraph
from ..stealth import StealthEngine
import os
from ..config import get_config_dir
from .swarm import SwarmRouter, SwarmTask
from .learning import ContinuousLearning, Experience

logger = logging.getLogger(__name__)

__all__ = [
    "AgentCore",
    "AgentMode",
    "AgentStatus",
    "AgentGoal",
    "AgentResult",
    "SwarmRouter",
    "SwarmTask",
    "ContinuousLearning",
    "Experience",
]


class AgentMode(StrEnum):
    REGISTRY = "registry"
    AUTONOMOUS = "autonomous"
    HYBRID = "hybrid"
    INTERACTIVE = "interactive"


class AgentStatus(StrEnum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    VALIDATING = "validating"
    RECOVERING = "recovering"
    REFLECTING = "reflecting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentGoal:
    description: str = ""
    target: str = ""
    constraints: dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    timeout: float = 600.0


@dataclass
class AgentResult:
    goal: str = ""
    success: bool = False
    summary: str = ""
    plan: ExecutionPlan | None = None
    duration_ms: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentCore:
    def __init__(self, mode: AgentMode = AgentMode.REGISTRY) -> None:
        self._mode = mode
        self._status = AgentStatus.IDLE
        self._registry = ToolRegistry()
        self._planner = Planner()
        self._executor = Executor(self._registry)
        self._validator = Validator()
        self._memory = MemoryManager()
        self._context = ContextManager(memory=self._memory)
        self._providers = ProviderManager.get_instance()
        self._workflow_engine = WorkflowEngine()
        self._event_bus = get_event_bus()

        # Load external plugins
        try:
            from siyarix.plugins.loader import PluginLoader
            plugin_loader = PluginLoader(self._registry, self._providers)
            plugin_loader.load_all()
        except Exception as e:
            logger.warning(f"Failed to initialize plugin loader: {e}")

        # Initialize notifications
        try:
            from siyarix.notifications import NotificationDispatcher
            self._notifications = NotificationDispatcher()
        except Exception as e:
            logger.warning(f"Failed to initialize notifications: {e}")
        self._history: list[AgentResult] = []
        self._kg_path = get_config_dir() / "knowledge_graph.json"
        self._knowledge_graph = KnowledgeGraph()
        self._usage_tracker = UsageTracker()
        self._stealth = StealthEngine()
        self._max_tokens_per_session = int(os.getenv("SIYARIX_MAX_TOKENS", "100000"))
        self._max_cost_usd = float(os.getenv("SIYARIX_MAX_COST_USD", "2.00"))

    @property
    def status(self) -> AgentStatus:
        return self._status

    @property
    def mode(self) -> AgentMode:
        return self._mode

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def planner(self) -> Planner:
        return self._planner

    @property
    def executor(self) -> Executor:
        return self._executor

    @property
    def validator(self) -> Validator:
        return self._validator

    @property
    def memory(self) -> MemoryManager:
        return self._memory

    @property
    def providers(self) -> ProviderManager:
        return self._providers

    @property
    def context(self) -> ContextManager:
        return self._context

    @property
    def stealth(self) -> StealthEngine:
        return self._stealth

    async def _check_budget(self) -> None:
        record = self._usage_tracker.session_totals()
        if record.total_tokens >= self._max_tokens_per_session:
            raise BudgetExceededError(
                f"Session token limit {self._max_tokens_per_session} reached."
            )
        if record.estimated_cost_usd >= self._max_cost_usd:
            raise BudgetExceededError(
                f"Session cost limit ${self._max_cost_usd:.2f} reached."
            )

    async def start(self) -> None:
        import signal
        import asyncio
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
            except NotImplementedError:
                pass

        if self._kg_path.exists():
            self._knowledge_graph.load_json(str(self._kg_path))
            logger.info("Loaded knowledge graph: %d nodes", len(self._knowledge_graph._nodes))

        if os.getenv("SIYARIX_STEALTH") == "1":
            try:
                from ..stealth import StealthEngine
                self._stealth = StealthEngine()
                self._stealth.enable()
                logger.info("Stealth mode active")
            except ImportError:
                pass

        await self.initialize()

        # Register custom _subagent executor for playbooks/swarms
        async def _subagent_handler(step: Any) -> dict[str, Any]:
            role = step.args.get("role", "assistant")
            goal_desc = step.args.get("goal", step.command)
            try:
                res = await self.execute_subagent(role, goal_desc)
                return {"status": "success", "findings": len(res.findings)}
            except Exception as e:
                return {"status": "error", "error": str(e)}
        self._executor.register_executor("_subagent", _subagent_handler)

    async def shutdown(self) -> None:
        logger.info("Siyarix shutting down gracefully...")
        if hasattr(self._executor, 'close'):
            await self._executor.close(timeout=5.0)
        self._kg_path.parent.mkdir(parents=True, exist_ok=True)
        self._knowledge_graph.save_json(str(self._kg_path))
        if hasattr(self._providers, '_state') and hasattr(self._providers._state, 'save'):
            self._providers._state.save()
        logger.info("Shutdown complete.")

    async def initialize(self) -> None:
        self._registry.discover_from_path()
        self._registry.scan_path()
        self._planner.build_index(
            [t.name for t in self._registry._graph.all_tools()],
            tool_registry=self._registry,
        )
        await self._event_bus.emit(
            Event(
                type=EventType.AGENT_START,
                source="agent",
                data={"mode": self._mode.value, "tools": self._registry.stats()["total"]},
            )
        )

    async def execute_multi_wave(self, goal: AgentGoal, max_waves: int = 5) -> AgentResult:
        all_findings: list[dict[str, Any]] = []
        plan = None
        for wave in range(max_waves):
            wave_context = {
                "wave": wave,
                "previous_findings": all_findings[-20:],
                "goal": goal.description,
            }
            wave_goal = AgentGoal(
                description=goal.description,
                constraints={**goal.constraints, "context": wave_context},
            )
            wave_result = await self.execute_goal(wave_goal, plan)
            all_findings.extend(wave_result.findings)

            if not wave_result.findings:
                break

            if hasattr(self._planner, "plan_next_wave"):
                plan = self._planner.plan_next_wave(wave_result.findings, goal)
            else:
                plan = None

        return AgentResult(goal=goal.description, findings=all_findings, success=True)

    async def execute_goal(self, goal: AgentGoal, plan: ExecutionPlan | None = None) -> AgentResult:
        self._status = AgentStatus.PLANNING
        start = time.time()
        result = AgentResult(goal=goal.description)

        if self._mode == AgentMode.REGISTRY:
            return await self._execute_registry(goal, plan, start, result)
        elif self._mode == AgentMode.AUTONOMOUS:
            return await self._execute_autonomous(goal, plan, start, result)
        elif self._mode == AgentMode.HYBRID:
            return await self._execute_hybrid(goal, plan, start, result)
        else:
            return await self._execute_interactive(goal, plan, start, result)

    async def _execute_registry(
        self, goal: AgentGoal, plan: ExecutionPlan | None, start: float, result: AgentResult
    ) -> AgentResult:
        """Registry mode: heuristic planning with validation, no LLM, no reflection."""
        try:
            tool_names = [t.name for t in self._registry.list_tools()]
            if plan is None:
                plan = self._planner.decompose_goal(goal.description, tool_names)
            result.plan = plan
            # Progress tracking
            step_progress: dict[str, str] = {}

            def on_step(s: PlanStep) -> None:
                step_id = s.id
                old_status = step_progress.get(step_id, "pending")
                if old_status != s.status.value:
                    step_progress[step_id] = s.status.value
                    from ..events import emit_sync

                    emit_sync(
                        Event(
                            type=EventType.PLAN_STEP_START
                            if s.status.value == "running"
                            else EventType.PLAN_STEP_COMPLETE,
                            source="core.registry",
                            data={"step_id": step_id, "tool": s.tool, "status": s.status.value},
                        )
                    )

            self._executor.set_progress_callback(on_step)
            await self._validator.validate_plan(plan.steps)
            if hasattr(plan, "plan_type") and getattr(plan.plan_type, "value", None) == "dag":
                from ..workflow import WorkflowStatus
                nodes = [
                    {
                        "id": s.id,
                        "name": s.tool or s.description,
                        "step_fn": s.tool,
                        "args": s.args,
                        "timeout": s.timeout,
                    }
                    for s in plan.steps
                ]
                edges = [
                    {"source": dep, "target": s.id}
                    for s in plan.steps
                    for dep in s.dependencies
                ]
                workflow = self._workflow_engine.create_workflow(
                    name=goal.description,
                    description=goal.description,
                    nodes=nodes,
                    edges=edges,
                )
                wf_result = await self._workflow_engine.run_workflow(workflow)
                result.success = wf_result.status == WorkflowStatus.COMPLETED
            else:
                plan = await self._executor.execute_plan(plan)
                result.success = plan.status == PlanStatus.COMPLETED

            result.summary = self._generate_summary(plan)
            result.findings = self._extract_findings(plan)
        except Exception as e:
            result.success = False
            result.summary = f"Registry agent failed: {e}"
            logger.exception("Registry agent execution failed")
        result.duration_ms = (time.time() - start) * 1000
        self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
        self._history.append(result)
        return result

    async def _execute_autonomous(
        self, goal: AgentGoal, plan: ExecutionPlan | None, start: float, result: AgentResult
    ) -> AgentResult:
        """Autonomous mode: LLM-first planning, reflection, recovery."""
        try:
            await self._check_budget()
            if plan is None:
                from ..config import SettingsStore
                _settings = SettingsStore()
                _preferred = _settings.get("model_provider") or None
                provider, model = self._providers.select_provider(preferred=_preferred)
                async def llm_call(system_prompt: str, user_prompt: str, *, history: Any = None, **kwargs: Any) -> Any:
                    return await self._providers.complete(
                        provider, "", system_prompt, user_prompt, history=history, **kwargs
                    )
                tool_schemas = [
                    {"name": t.name, "description": t.description, "tags": t.tags, "category": getattr(t.category, 'value', str(t.category))}
                    for t in self._registry.list_tools()
                ]
                plan = await self._planner.llm_decompose_goal(
                    goal.description,
                    [t.name for t in self._registry.list_tools()],
                    llm_call=llm_call,
                    tool_schemas=tool_schemas,
                    history=self._context.get_history(),
                )
            result.plan = plan
            self._context.add_history(f"Goal: {goal.description}", "user")
            await self._validator.validate_plan(plan.steps)
            plan = await self._executor.execute_plan(plan)
            if plan.has_failures:
                for step in plan.failed_steps:
                    recovery = await self._validator.plan_recovery(
                        step, step.result.get("error", "")
                    )
                    if recovery.action == RecoveryAction.RETRY and recovery.modified_step:
                        idx = plan.steps.index(step)
                        plan.steps[idx] = recovery.modified_step
                        plan = await self._executor.execute_plan(plan)
                        break
            result.success = plan.status == PlanStatus.COMPLETED
            result.summary = self._generate_summary(plan)
            result.findings = self._extract_findings(plan)
        except Exception as e:
            result.success = False
            result.summary = f"Autonomous agent failed: {e}"
            logger.exception("Autonomous agent execution failed")
        result.duration_ms = (time.time() - start) * 1000
        self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
        self._history.append(result)
        return result

    async def _execute_hybrid(
        self, goal: AgentGoal, plan: ExecutionPlan | None, start: float, result: AgentResult
    ) -> AgentResult:
        """Hybrid mode: try autonomous (LLM) first, fall back to registry (heuristic)."""
        auto_result = await self._execute_autonomous(goal, plan, start, AgentResult(goal=goal.description))
        if auto_result.success:
            return auto_result

        logger.info("Autonomous execution failed, falling back to registry mode")

        completed_step_ids = {
            s.id for s in (auto_result.plan.steps if auto_result.plan else [])
            if s.status == StepStatus.COMPLETED
        }

        registry_plan = self._planner.decompose_goal(
            goal.description, [t.name for t in self._registry.list_tools()]
        )
        for step in registry_plan.steps:
            if step.tool in completed_step_ids:
                step.status = StepStatus.SKIPPED

        return await self._execute_registry(goal, registry_plan, start, AgentResult(goal=goal.description))

    async def _execute_interactive(
        self, goal: AgentGoal, plan: ExecutionPlan | None, start: float, result: AgentResult
    ) -> AgentResult:
        """Interactive mode: user-in-the-loop."""
        try:
            if plan is None:
                plan = self._planner.decompose_goal(
                    goal.description, [t.name for t in self._registry.list_tools()]
                )
            result.plan = plan

            print("\n--- Plan Preview ---")
            for step in plan.steps:
                print(f"[{step.id}] {step.tool}: {step.description}")
            print("--------------------\n")

            approval = input("Approve plan? [y/N]: ").strip().lower()
            if approval != 'y':
                result.success = False
                result.summary = "Plan rejected by user."
                return result

            plan = await self._executor.execute_plan(plan)
            result.success = plan.status == PlanStatus.COMPLETED
            result.summary = self._generate_summary(plan)
            result.findings = self._extract_findings(plan)
        except Exception as e:
            result.success = False
            result.summary = f"Interactive agent failed: {e}"
            logger.exception("Interactive agent execution failed")
        result.duration_ms = (time.time() - start) * 1000
        self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
        self._history.append(result)
        return result

    def _generate_summary(self, plan: ExecutionPlan) -> str:
        completed = len(plan.completed_steps)
        failed = len(plan.failed_steps)
        total = len(plan.steps)
        return f"Executed {total} steps: {completed} completed, {failed} failed. Progress: {plan.progress_pct:.0f}%"

    def _extract_findings(self, plan: ExecutionPlan) -> list[dict[str, Any]]:
        import hashlib
        def _make_finding_hash(finding: dict) -> str:
            key_parts = [
                finding.get("target", ""),
                finding.get("port", ""),
                finding.get("cve", finding.get("title", "")),
                finding.get("severity", ""),
            ]
            return hashlib.md5("|".join(str(p).lower() for p in key_parts).encode(), usedforsecurity=False).hexdigest()

        findings = []
        seen_keys: set[str] = set()
        for step in plan.steps:
            if not (step.status == StepStatus.COMPLETED and step.result):
                continue
            parsed = step.result.get("findings")
            if parsed and isinstance(parsed, list):
                for f in parsed:
                    dedup_key = _make_finding_hash(f)
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        findings.append(f)
                        self._ingest_finding_to_graph(f, discovered_by=step.tool)
            output = step.result.get("output", "")
            if output and not parsed:
                f_dict = {
                    "tool": step.tool,
                    "description": step.description,
                    "output_preview": output[:500],
                    "severity": "info",
                }
                findings.append(f_dict)
                self._ingest_finding_to_graph(f_dict, discovered_by=step.tool)
        return findings

    def _ingest_finding_to_graph(self, finding: dict[str, Any], discovered_by: str) -> None:
        from ..knowledge_graph import NodeType, EdgeType
        target = finding.get("target", "")
        host_node = None
        if target:
            host_node = self._knowledge_graph.add_node(
                NodeType.HOST, label=target, discovered_by=discovered_by,
                ip=finding.get("ip", ""), hostname=finding.get("hostname", "")
            )
        if finding.get("cve") or finding.get("severity"):
            vuln_node = self._knowledge_graph.add_node(
                NodeType.VULNERABILITY, label=finding.get("cve", finding.get("title", finding.get("description", "vuln"))),
                severity=finding.get("severity", ""), cve=finding.get("cve", ""),
                discovered_by=discovered_by,
            )
            if host_node:
                self._knowledge_graph.add_edge(host_node.node_id, vuln_node.node_id, EdgeType.HAS_VULN)

    def create_subagent(self, role: str, mode: AgentMode = AgentMode.AUTONOMOUS) -> 'AgentCore':
        """Create a specialized sub-agent that shares this agent's knowledge graph."""
        subagent = AgentCore(mode=mode)
        subagent._knowledge_graph = self._knowledge_graph  # Share memory
        logger.info(f"Created sub-agent with role: {role}")
        return subagent

    async def execute_subagent(self, role: str, goal: str) -> AgentResult:
        """Create and run a subagent for a specific goal."""
        subagent = self.create_subagent(role)
        await subagent.start()
        try:
            result = await subagent.execute_goal(AgentGoal(description=goal))
            return result
        finally:
            await subagent.shutdown()

    def stats(self) -> dict[str, Any]:
        return {
            "mode": self._mode.value,
            "status": self._status.value,
            "registry": self._registry.stats(),
            "history": len(self._history),
        }
