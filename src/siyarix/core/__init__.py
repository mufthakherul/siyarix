# SPDX-License-Identifier: AGPL-3.0-or-later
"""Core agent system with mode-aware planners and executors."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..registry import ToolRegistry
from ..planner import Planner, ExecutionPlan
from ..planner_registry import RegistryPlanner
from ..planner_autonomous import AutonomousPlanner
from ..executor_registry import RegistryExecutor
from ..executor_autonomous import AutonomousExecutor
from ..validators import Validator
from ..context import ContextManager
from ..memory import MemoryManager
from ..providers import ProviderManager
from ..providers.usage import UsageTracker
from ..workflow import WorkflowEngine
from ..events import Event, EventType, get_event_bus
from ..exceptions import BudgetExceededError
from ..knowledge_graph import KnowledgeGraph
from ..stealth import StealthEngine
from ..config import get_config_dir, SettingsStore
from ..permission_gate import PermissionGate
from .swarm import SwarmRouter, SwarmTask
from ..offline_store import OfflineStore
from ..metrics import get_metrics
from .mixins import ExecutionMixin, GraphMixin

logger = logging.getLogger(__name__)

__all__ = [
    "AgentCore",
    "AgentMode",
    "AgentStatus",
    "AgentGoal",
    "AgentResult",
    "SwarmRouter",
    "SwarmTask",
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


class AgentCore(ExecutionMixin, GraphMixin):
    """Central orchestrator with mode-aware planners and executors.

    Uses PlannerRouter for mode dispatch and dedicated executors for
    registry (tool-based) and autonomous (shell-command) execution.
    """

    def __init__(
        self,
        mode: AgentMode = AgentMode.REGISTRY,
        registry: ToolRegistry | None = None,
        db_path: str | Path | None = None,
        progress_callback: Any | None = None,
    ) -> None:
        self._mode = mode
        self._status = AgentStatus.IDLE
        self._registry = registry or ToolRegistry()
        self._planner_registry = RegistryPlanner()
        self._planner_autonomous = AutonomousPlanner()
        self._planner = Planner(
            autonomous_planner=self._planner_autonomous,
            registry_planner=self._planner_registry,
        )

        # PermissionGate — enforce safe mode boundaries
        _settings = SettingsStore()
        _safe_mode = os.getenv("SIYARIX_SAFE_MODE", "0") == "1" or _settings.get(
            "_safe_mode", default=False
        )
        self._permission_gate = PermissionGate() if _safe_mode else None

        self._executor_registry = RegistryExecutor(
            self._registry,
            permission_gate=self._permission_gate,
        )
        self._executor_autonomous = AutonomousExecutor(
            registry=self._registry,
            permission_gate=self._permission_gate,
        )
        self._validator = Validator()
        self._memory = MemoryManager()
        self._context = ContextManager(memory=self._memory)
        self._providers = ProviderManager.get_instance()
        self._workflow_engine = WorkflowEngine()
        self._event_bus = get_event_bus()
        self._store = OfflineStore(db_path=db_path)
        self._metrics = get_metrics()

        try:
            from siyarix.plugins.loader import PluginLoader

            plugin_loader = PluginLoader(self._registry, self._providers)
            plugin_loader.load_all()
        except Exception as e:
            logger.warning("Failed to initialize plugin loader: %s", e)

        try:
            from siyarix.notifications import NotificationDispatcher

            self._notifications = NotificationDispatcher()
        except Exception as e:
            logger.warning("Failed to initialize notifications: %s", e)

        self._progress_callback = progress_callback
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
    def planner_registry(self) -> RegistryPlanner:
        return self._planner_registry

    @property
    def planner_autonomous(self) -> AutonomousPlanner:
        return self._planner_autonomous

    @property
    def executor_registry(self) -> RegistryExecutor:
        return self._executor_registry

    @property
    def executor_autonomous(self) -> AutonomousExecutor:
        return self._executor_autonomous

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
            raise BudgetExceededError(f"Session cost limit ${self._max_cost_usd:.2f} reached.")

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
            try:
                self._knowledge_graph.load_json(str(self._kg_path))
                logger.info("Loaded knowledge graph: %d nodes", len(self._knowledge_graph._nodes))
            except Exception:
                logger.debug("Failed to load knowledge graph")

        if os.getenv("SIYARIX_STEALTH") == "1":
            try:
                self._stealth = StealthEngine()
                self._stealth.enable()
                logger.info("Stealth mode active")
            except ImportError:
                logger.warning("Stealth dependencies not available", exc_info=True)

        await self.initialize()

        async def _subagent_handler(step: Any) -> dict[str, Any]:
            role = step.args.get("role", "assistant")
            goal_desc = step.args.get("goal", step.command)
            try:
                res = await self.execute_subagent(role, goal_desc)
                return {"status": "success", "findings": len(res.findings)}
            except Exception:
                logger.exception("Subagent execution failed")
                return {"status": "error", "error": "Subagent execution failed"}

        self._executor_registry.register_executor("_subagent", _subagent_handler)

    async def shutdown(self) -> None:
        logger.info("Siyarix shutting down gracefully...")
        await self._executor_registry.close(timeout=5.0)
        await self._executor_autonomous.close(timeout=5.0)
        self._kg_path.parent.mkdir(parents=True, exist_ok=True)
        self._knowledge_graph.save_json(str(self._kg_path))
        if hasattr(self._providers, "_state") and hasattr(self._providers._state, "save"):
            self._providers._state.save()
        self._store.close()
        logger.info("Shutdown complete.")

    async def initialize(self) -> None:
        self._registry.discover_from_path()
        self._registry.scan_path()
        tool_names = [t.name for t in self._registry._graph.all_tools()]
        self._planner_registry.build_index(tool_names, tool_registry=self._registry)
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
        try:
            from ..performance import PerformanceOptimizer

            PerformanceOptimizer().refresh_resources()
        except Exception:
            pass

        try:
            from ..session_branching import SessionBranchManager  # type: ignore[attr-defined]

            SessionBranchManager().add_compaction(f"start_goal_{int(time.time())}")
        except Exception:
            pass

        self._status = AgentStatus.PLANNING
        start = time.time()
        result = AgentResult(goal=goal.description)

        async def _goal_start(args: dict[str, Any]) -> dict[str, Any]:
            return {"status": "started", "goal": goal.description}

        self._workflow_engine.register_step("execute_goal_start", _goal_start)

        if self._mode == AgentMode.REGISTRY:
            result = await self._execute_registry(goal, plan, start, result)
        elif self._mode == AgentMode.AUTONOMOUS:
            result = await self._execute_autonomous(goal, plan, start, result)
        elif self._mode == AgentMode.HYBRID:
            result = await self._execute_hybrid(goal, plan, start, result)
        else:
            result = await self._execute_interactive(goal, plan, start, result)

        self._workflow_engine.register_step("execute_goal_end", {"success": result.success})  # type: ignore[arg-type]

        return result

    def _generate_summary(self, plan: ExecutionPlan) -> str:
        completed = len(plan.completed_steps)
        failed = len(plan.failed_steps)
        total = len(plan.steps)
        return f"Executed {total} steps: {completed} completed, {failed} failed. Progress: {plan.progress_pct:.0f}%"

    def create_subagent(self, role: str, mode: AgentMode = AgentMode.AUTONOMOUS) -> "AgentCore":
        subagent = AgentCore(mode=mode)
        subagent._knowledge_graph = self._knowledge_graph
        logger.info("Created sub-agent with role: %s", role)
        return subagent

    async def execute_subagent(self, role: str, goal: str) -> AgentResult:
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
            "planner_router": self._planner.stats(),
        }
