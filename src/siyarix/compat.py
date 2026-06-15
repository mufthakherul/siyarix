# SPDX-License-Identifier: AGPL-3.0-or-later
"""Core engine primitives — ExecutionMode, ExecutionEngine, SessionKernel, IntentRouter.

Provides the foundational types used by the CLI and chat subsystems for
session management, intent routing, and execution engine integration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from siyarix.config import get_config_dir
from .registry import RiskLevel

logger = logging.getLogger(__name__)


class ExecutionMode(StrEnum):
    REGISTRY = "registry"
    OFFLINE = "offline"
    AUTONOMOUS = "autonomous"
    INTEGRATED = "integrated"


class SessionPersistenceLevel(StrEnum):
    """Session persistence boundary."""

    EPHEMERAL = "ephemeral"
    WORKSPACE = "workspace"
    ORG_SHARED = "org_shared"


@dataclass
class OperationCard:
    """Operation tracking card for UX timeline/state."""

    operation_id: str
    instruction: str
    state: str = "planned"
    mode: str = "integrated"
    risk_tier: str = "low"
    retries: int = 0
    artifacts: list[str] = field(default_factory=list)
    audit_hash: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


@dataclass
class SessionContext:
    """Canonical session context for routing, policy, and UX rendering."""

    session_id: str
    identity: str = "local-user"
    objective: str = ""
    scope: str = ""
    policy_context: dict[str, Any] = field(default_factory=dict)
    model_context: dict[str, Any] = field(default_factory=dict)
    tool_context: dict[str, Any] = field(default_factory=dict)
    persistence: SessionPersistenceLevel = SessionPersistenceLevel.WORKSPACE
    operations: list[OperationCard] = field(default_factory=list)


class SessionKernel:
    """Manage session state and operation cards."""

    def __init__(self, base_dir: Path | None = None) -> None:
        root = base_dir or get_config_dir() / "kernel_sessions"
        root.mkdir(parents=True, exist_ok=True)
        self._root = root

    def start(
        self,
        objective: str = "",
        scope: str = "",
        identity: str = "local-user",
        persistence: SessionPersistenceLevel = SessionPersistenceLevel.WORKSPACE,
    ) -> SessionContext:
        return SessionContext(
            session_id=uuid4().hex,
            identity=identity,
            objective=objective,
            scope=scope,
            persistence=persistence,
        )

    def add_operation(
        self, session: SessionContext, instruction: str, mode: str, risk_tier: str
    ) -> OperationCard:
        op = OperationCard(
            operation_id=uuid4().hex,
            instruction=instruction,
            mode=mode,
            risk_tier=risk_tier,
        )
        session.operations.append(op)
        return op

    def update_operation(
        self,
        session: SessionContext,
        operation_id: str,
        *,
        state: str | None = None,
        retries: int | None = None,
        artifact: str | None = None,
        audit_hash: str | None = None,
    ) -> OperationCard | None:
        target = next((o for o in session.operations if o.operation_id == operation_id), None)
        if not target:
            return None
        if state is not None:
            target.state = state
        if retries is not None:
            target.retries = retries
        if artifact:
            target.artifacts.append(artifact)
        if audit_hash is not None:
            target.audit_hash = audit_hash
        target.updated_at = datetime.now(tz=UTC).isoformat()
        return target

    def save(self, session: SessionContext) -> Path:
        path = self._root / f"{session.session_id}.json"
        data = asdict(session)
        data["persistence"] = session.persistence.value
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def load(self, session_id: str) -> SessionContext | None:
        path = self._root / f"{session_id}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        operations = [OperationCard(**row) for row in data.get("operations", [])]
        return SessionContext(
            session_id=data["session_id"],
            identity=data.get("identity", "local-user"),
            objective=data.get("objective", ""),
            scope=data.get("scope", ""),
            policy_context=data.get("policy_context", {}) or {},
            model_context=data.get("model_context", {}) or {},
            tool_context=data.get("tool_context", {}) or {},
            persistence=SessionPersistenceLevel(data.get("persistence", "workspace")),
            operations=operations,
        )


@dataclass
class EngineResult:
    success: bool = False
    summary: str = ""
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    step_results: list[Any] = field(default_factory=list)
    raw_output: str = ""
    duration_ms: float = 0.0
    retries_performed: int = 0
    plan_id: str = ""
    error_message: str = ""


class ExecutionEngine:
    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.INTEGRATED,
        registry: Any = None,
        config: dict[str, Any] | None = None,
        session_logger: Any = None,
    ) -> None:
        self._mode = mode
        self._registry = registry
        self._config = config or {}
        self._session_logger = session_logger
        self._kill_switch = None
        self._planner = None

    def _build_context(self) -> dict[str, Any]:
        return {"mode": self._mode.value if hasattr(self._mode, "value") else str(self._mode)}

    async def plan(self, instruction: str) -> Any:
        from .planner import Planner
        from .planner_registry import RegistryPlanner

        planner = RegistryPlanner()
        tools = [t.name for t in self._registry.list_tools()] if self._registry else []
        return planner.plan(instruction, tools)

    async def execute(self, goal: str, **kwargs: Any) -> EngineResult:
        from .core import AgentCore, AgentMode, AgentGoal
        from .models import StepResult

        mode_map = {
            ExecutionMode.REGISTRY: AgentMode.REGISTRY,
            ExecutionMode.OFFLINE: AgentMode.REGISTRY,
            ExecutionMode.AUTONOMOUS: AgentMode.AUTONOMOUS,
            ExecutionMode.INTEGRATED: AgentMode.HYBRID,
        }
        agent = AgentCore(mode=mode_map.get(self._mode, AgentMode.HYBRID))
        await agent.initialize()
        agent_goal = AgentGoal(description=goal)
        result = await agent.execute_goal(agent_goal)
        step_results = []
        plan_id = ""
        if result.plan:
            plan_id = result.plan.id
            for i, step in enumerate(result.plan.steps):
                sr = StepResult(
                    step_id=str(i + 1),
                    status=step.status,
                    output=step.result.get("output", "") if step.result else "",
                    error=step.result.get("error", "") if step.result else "",
                )
                step_results.append(sr)

        persist = kwargs.get("persist", False)
        if persist and result.findings:
            try:
                from .offline_store import OfflineStore

                store = OfflineStore()
                store.save_scan(goal, result.findings, mode=self._mode.value if hasattr(self._mode, "value") else str(self._mode), plan_id=plan_id)
                if result.plan:
                    step_dicts = [
                        {
                            "tool": s.tool,
                            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
                            "description": s.description,
                        }
                        for s in result.plan.steps
                    ]
                    store.save_plan(plan_id, result.plan.goal or goal, step_dicts)
            except Exception:
                logger.exception("Failed to persist execution results")

        return EngineResult(
            success=result.success,
            summary=result.summary,
            all_findings=result.findings,
            step_results=step_results,
            plan_id=plan_id,
        )

    async def run(self, goal: str, **kwargs: Any) -> EngineResult:
        return await self.execute(goal)

    async def resume(self, plan_id: str, interactive: bool = False) -> EngineResult:
        """Resume execution of a previously saved plan."""
        return await self.execute(f"Resume plan: {plan_id}")


class IntentRoute:
    def __init__(
        self, mode: str = "general", risk_tier: Any = None, requires_confirmation: bool = False
    ) -> None:
        self.mode = mode
        self.risk_tier = risk_tier or RiskTier("low")
        self.requires_confirmation = requires_confirmation


RiskTier = RiskLevel


class IntentRouter:
    def route(self, text: str, **kwargs: Any) -> IntentRoute:
        text_lower = text.lower()
        if any(kw in text_lower for kw in ("scan", "nmap", "port scan")):
            return IntentRoute(mode="scan", risk_tier=RiskTier("medium"))
        if any(kw in text_lower for kw in ("recon", "enumerate", "discover")):
            return IntentRoute(mode="recon", risk_tier=RiskTier("low"))
        if any(kw in text_lower for kw in ("web", "http", "nikto", "nuclei")):
            return IntentRoute(mode="web", risk_tier=RiskTier("medium"))
        if any(kw in text_lower for kw in ("brute", "crack", "password")):
            return IntentRoute(mode="brute", risk_tier=RiskTier("high"), requires_confirmation=True)
        if any(kw in text_lower for kw in ("exploit", "metasploit", "attack")):
            return IntentRoute(
                mode="exploit", risk_tier=RiskTier("high"), requires_confirmation=True
            )
        return IntentRoute(mode="general", risk_tier=RiskTier("low"))

__all__ = [
    "ExecutionMode",
    "SessionPersistenceLevel",
    "OperationCard",
    "SessionContext",
    "SessionKernel",
    "EngineResult",
    "ExecutionEngine",
    "IntentRoute",
    "IntentRouter",
]
