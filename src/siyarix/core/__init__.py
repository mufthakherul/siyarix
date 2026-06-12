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
from ..workflow import WorkflowEngine
from ..events import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)

__all__ = [
    "AgentCore",
    "AgentMode",
    "AgentStatus",
    "AgentGoal",
    "AgentResult",
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
        await self._event_bus.emit(
            Event(
                type=EventType.AGENT_START,
                source="agent",
                data={"mode": self._mode.value, "tools": self._registry.stats()["total"]},
            )
        )

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
            if plan is None:
                plan = self._planner.decompose_goal(
                    goal.description, [t.name for t in self._registry.list_tools()]
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
        """Hybrid mode: try autonomous (LLM) first, fall back to registry (heuristic).

        This is NOT a standalone execution — it orchestrates between
        autonomous and registry modes, combining their strengths.
        """
        self._mode = AgentMode.AUTONOMOUS
        auto_result = await self._execute_autonomous(goal, plan, start, AgentResult(goal=goal.description))
        if auto_result.success:
            result.success = True
            result.summary = auto_result.summary
            result.findings = auto_result.findings
            result.plan = auto_result.plan
            result.duration_ms = auto_result.duration_ms
            self._history[-1] = result  # replace auto's history entry
            self._status = AgentStatus.COMPLETED
            return result

        logger.info("Autonomous execution failed, falling back to registry mode")
        self._history.pop()  # remove auto's failed history entry
        self._mode = AgentMode.REGISTRY
        reg_result = await self._execute_registry(goal, plan, start, AgentResult(goal=goal.description))
        result.success = reg_result.success
        result.summary = f"Hybrid (autonomous failed → registry): {reg_result.summary}"
        result.findings = reg_result.findings
        result.plan = reg_result.plan
        result.duration_ms = (time.time() - start) * 1000
        self._history[-1] = result  # replace registry's history entry
        self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
        return result

    async def _execute_interactive(
        self, goal: AgentGoal, plan: ExecutionPlan | None, start: float, result: AgentResult
    ) -> AgentResult:
        """Interactive mode: lightweight, user-in-the-loop, minimal automation."""
        try:
            if plan is None:
                plan = self._planner.decompose_goal(
                    goal.description, [t.name for t in self._registry.list_tools()]
                )
            result.plan = plan
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
        findings = []
        seen_keys: set[str] = set()
        for step in plan.steps:
            if not (step.status == StepStatus.COMPLETED and step.result):
                continue
            parsed = step.result.get("findings")
            if parsed and isinstance(parsed, list):
                for f in parsed:
                    dedup_key = f"{f.get('tool', '')}:{f.get('title', '')}:{f.get('target', '')}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        findings.append(f)
            output = step.result.get("output", "")
            if output and not parsed:
                findings.append(
                    {
                        "tool": step.tool,
                        "description": step.description,
                        "output_preview": output[:500],
                        "severity": "info",
                    }
                )
        return findings

    def stats(self) -> dict[str, Any]:
        return {
            "mode": self._mode.value,
            "status": self._status.value,
            "registry": self._registry.stats(),
            "history": len(self._history),
        }
