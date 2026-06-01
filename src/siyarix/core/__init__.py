# SPDX-License-Identifier: AGPL-3.0-or-later
"""Core agent system with goal decomposition, execution, and self-reflection."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..registry import ToolRegistry
from ..planner import Planner, ExecutionPlan, PlanStatus, StepStatus
from ..executor import Executor
from ..validator import Validator, RecoveryAction
from ..context import ContextManager
from ..memory import MemoryManager
from ..providers import ProviderManager
from ..workflow import WorkflowEngine
from ..events import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)


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
        self._context = ContextManager()
        self._memory = MemoryManager()
        self._providers = ProviderManager()
        self._workflow_engine = WorkflowEngine()
        self._event_bus = get_event_bus()
        self._history: list[AgentResult] = []

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

    async def initialize(self) -> None:
        self._registry.discover_from_path()
        self._registry.scan_path()
        self._planner.build_index(
            [t.name for t in self._registry._graph.all_tools()],
            tool_registry=self._registry,
        )
        await self._event_bus.emit(Event(
            type=EventType.AGENT_START, source="agent",
            data={"mode": self._mode.value, "tools": self._registry.stats()["total"]},
        ))

    async def execute_goal(self, goal: AgentGoal, plan: ExecutionPlan | None = None) -> AgentResult:
        self._status = AgentStatus.PLANNING
        start = time.time()
        result = AgentResult(goal=goal.description)
        try:
            if plan is None:
                plan = self._planner.decompose_goal(
                    goal.description, [t.name for t in self._registry.list_tools()])
            result.plan = plan
            self._context.add_history(f"Goal: {goal.description}", "user")
            await self._validator.validate_plan(plan.steps)
            plan = await self._executor.execute_plan(plan)
            if plan.has_failures:
                for step in plan.failed_steps:
                    recovery = await self._validator.plan_recovery(step, step.result.get("error", ""))
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
            result.summary = f"Agent failed: {e}"
            logger.exception("Agent execution failed")
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
        findings = []
        for step in plan.steps:
            if step.status == StepStatus.COMPLETED and step.result:
                output = step.result.get("output", "")
                if output:
                    findings.append({"tool": step.tool, "description": step.description, "output_preview": output[:500]})
        return findings

    def stats(self) -> dict[str, Any]:
        return {
            "mode": self._mode.value,
            "status": self._status.value,
            "registry": self._registry.stats(),
            "history": len(self._history),
        }
