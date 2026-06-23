# SPDX-License-Identifier: AGPL-3.0-or-later
"""Planner router — dispatches requests to AutonomousPlanner or RegistryPlanner based on execution mode.

Acts as the unified entry point for all planning. Routes to the appropriate
specialised planner and handles integrated-mode fallback logic.
"""

from __future__ import annotations

import logging
from typing import Any

from .models import (
    ExecutionPlan,
    PlanStatus,
    PlanStep,
    PlanType,
    StepResult,
    StepStatus,
    StepType,
)
from .planner_autonomous import AutonomousPlanner
from .planner_registry import TOOL_ALTERNATIVES, RegistryPlanner

logger = logging.getLogger(__name__)

# Re-export models for backward compatibility
__all__ = [
    "ExecutionPlan",
    "PlanStatus",
    "PlanStep",
    "PlanType",
    "StepResult",
    "StepStatus",
    "StepType",
    "Planner",
    "TOOL_ALTERNATIVES",
]


class Planner:
    """Unified planner router — dispatches to the right planner by mode.

    Modes
    -----
    - ``autonomous``  → AutonomousPlanner (LLM-only, no heuristic fallback)
    - ``offline`` / ``registry`` → RegistryPlanner (heuristic-only)
    - ``integrated``  → try AutonomousPlanner first; fall back to RegistryPlanner
                        on any failure. If provider is ``"registry"``, skip LLM.
    """

    def __init__(
        self,
        autonomous_planner: AutonomousPlanner | None = None,
        registry_planner: RegistryPlanner | None = None,
    ) -> None:
        self._autonomous = autonomous_planner or AutonomousPlanner()
        self._registry = registry_planner or RegistryPlanner()
        self._plans: dict[str, ExecutionPlan] = {}

    @property
    def autonomous_planner(self) -> AutonomousPlanner:
        return self._autonomous

    @property
    def registry_planner(self) -> RegistryPlanner:
        return self._registry

    # ── Public routing API ────────────────────────────────────────────────

    async def plan(
        self,
        goal: str,
        mode: str = "integrated",
        provider: str | None = None,
        available_tools: list[str] | None = None,
        llm_call: Any = None,
        tool_schemas: list[dict] | None = None,
        system_prompt: str | None = None,
        platform: str | None = None,
        history: list[dict] | None = None,
        is_first_call: bool | None = None,
        **kwargs: Any,
    ) -> ExecutionPlan:
        """Route the planning request based on execution mode.

        Parameters
        ----------
        goal:
            The user's request to plan.
        mode:
            One of ``"autonomous"``, ``"registry"``, ``"offline"``, ``"integrated"``.
        provider:
            Model provider name. When ``"registry"`` in integrated mode, skips LLM.
        available_tools:
            List of tool names available for registry/offline mode.
        llm_call:
            Async callable for LLM interactions (required for autonomous mode).
        tool_schemas:
            Full tool metadata for the LLM (first-call context).
        system_prompt:
            Custom system prompt for the LLM.
        platform:
            Pre-built platform context string.
        history:
            Conversation history for the LLM.
        is_first_call:
            Override session first-call detection in AutonomousPlanner.
        """
        mode_lower = mode.lower()

        if mode_lower in ("registry", "offline"):
            logger.debug("Planner: routing to RegistryPlanner (%s mode)", mode_lower)
            return self._registry.plan(goal, available_tools=available_tools)

        if mode_lower == "autonomous":
            logger.debug("Planner: routing to AutonomousPlanner (autonomous mode)")
            return await self._autonomous.plan(
                goal,
                system_prompt=system_prompt,
                platform=platform,
                llm_call=llm_call,
                tool_schemas=tool_schemas,
                available_tools=available_tools,
                history=history,
                is_first_call=is_first_call,
            )

        # ── Integrated mode ────────────────────────────────────────────────
        provider_lower = (provider or "").lower()

        # If provider is explicitly "registry", skip LLM entirely
        if provider_lower == "registry":
            logger.debug("Planner: integrated mode with registry provider → RegistryPlanner")
            return self._registry.plan(goal, available_tools=available_tools)

        # Try AutonomousPlanner first
        logger.debug("Planner: integrated mode → trying AutonomousPlanner")
        try:
            plan = await self._autonomous.plan(
                goal,
                system_prompt=system_prompt,
                platform=platform,
                llm_call=llm_call,
                tool_schemas=tool_schemas,
                available_tools=available_tools,
                history=history,
                is_first_call=is_first_call,
            )
            if plan.steps:
                logger.debug("Planner: AutonomousPlanner succeeded in integrated mode")
                return plan
        except Exception as exc:
            logger.warning("Planner: AutonomousPlanner failed in integrated mode: %s", exc)

        # Fall back to RegistryPlanner
        logger.info("Planner: integrated mode → falling back to RegistryPlanner")
        return self._registry.plan(goal, available_tools=available_tools)

    # ── Backward-compatible API ───────────────────────────────────────────

    def decompose_goal(self, goal: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        """Backward-compatible wrapper — delegates to RegistryPlanner."""
        return self._registry.decompose_goal(goal, available_tools)

    def create_from_template(
        self,
        template_name: str,
        target: str,
        overrides: dict[str, Any] | None = None,
        available_tools: set[str] | None = None,
    ) -> ExecutionPlan:
        """Backward-compatible wrapper — delegates to RegistryPlanner."""
        return self._registry.create_from_template(
            template_name, target, overrides, available_tools
        )

    async def llm_decompose_goal(
        self,
        goal: str,
        available_tools: list[str],
        llm_call: Any,
        tool_schemas: list[dict] | None = None,
        system_prompt: str | None = None,
        history: list[dict] | None = None,
    ) -> ExecutionPlan:
        """Backward-compatible wrapper — delegates to AutonomousPlanner."""
        return await self._autonomous.plan(
            goal,
            system_prompt=system_prompt,
            llm_call=llm_call,
            tool_schemas=tool_schemas,
            available_tools=available_tools,
            history=history,
        )

    def resolve_alternatives(
        self, template_name: str, available_tools: set[str]
    ) -> list[dict[str, Any]]:
        """Backward-compatible wrapper — delegates to RegistryPlanner."""
        return self._registry.resolve_alternatives(template_name, available_tools)

    def build_index(self, available_tools: list[str], tool_registry: Any = None) -> None:
        """Backward-compatible wrapper — delegates to RegistryPlanner."""
        self._registry.build_index(available_tools, tool_registry)

    def create_plan(
        self,
        goal: str,
        plan_type: PlanType = PlanType.SEQUENTIAL,
        steps: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        plan = self._registry.create_plan(goal, plan_type, steps, context)
        self._plans[plan.id] = plan
        return plan

    def adapt_plan(self, plan: ExecutionPlan, failed_step: PlanStep, error: str) -> ExecutionPlan:
        return self._registry.adapt_plan(plan, failed_step, error)

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        return (
            self._registry.get_plan(plan_id)
            or self._autonomous.get_plan(plan_id)
            or self._plans.get(plan_id)
        )

    def list_plans(self, status: PlanStatus | None = None) -> list[ExecutionPlan]:
        registry_plans = self._registry.list_plans(status)
        auto_plans = self._autonomous.list_plans(status)
        seen = {p.id for p in registry_plans}
        return registry_plans + [p for p in auto_plans if p.id not in seen]

    def stats(self) -> dict[str, Any]:
        registry_stats = self._registry.stats()
        auto_stats = self._autonomous.stats()
        total = registry_stats.get("total_plans", 0) + auto_stats.get("total_plans", 0)
        return {
            "total_plans": total,
            "active": registry_stats.get("active", 0) + auto_stats.get("active", 0),
            "completed": registry_stats.get("completed", 0) + auto_stats.get("completed", 0),
            "templates": registry_stats.get("templates", []),
            "router": {"mode": "multi", "sub_planners": ["autonomous", "registry"]},
            "registry": registry_stats,
            "autonomous": auto_stats,
        }
