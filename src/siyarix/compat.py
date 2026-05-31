# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backward-compatible wrappers for old module names."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ExecutionMode(StrEnum):
    REGISTRY = "registry"
    AUTONOMOUS = "autonomous"
    INTEGRATED = "integrated"


@dataclass
class EngineResult:
    success: bool = False
    summary: str = ""
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    duration_ms: float = 0.0


class ExecutionEngine:
    def __init__(self, mode: ExecutionMode = ExecutionMode.INTEGRATED,
                 registry: Any = None, config: dict[str, Any] | None = None) -> None:
        self._mode = mode
        self._registry = registry
        self._config = config or {}

    async def execute(self, goal: str, **kwargs: Any) -> EngineResult:
        from .core import AgentCore, AgentMode, AgentGoal
        mode_map = {
            ExecutionMode.REGISTRY: AgentMode.REGISTRY,
            ExecutionMode.AUTONOMOUS: AgentMode.AUTONOMOUS,
            ExecutionMode.INTEGRATED: AgentMode.HYBRID,
        }
        agent = AgentCore(mode=mode_map.get(self._mode, AgentMode.HYBRID))
        await agent.initialize()
        agent_goal = AgentGoal(description=goal)
        result = await agent.execute_goal(agent_goal)
        return EngineResult(
            success=result.success, summary=result.summary,
            all_findings=result.findings,
        )

    async def run(self, goal: str, **kwargs: Any) -> EngineResult:
        return await self.execute(goal)


class IntentRoute:
    def __init__(self, mode: str = "general", risk_tier: Any = None, requires_confirmation: bool = False) -> None:
        self.mode = mode
        self.risk_tier = risk_tier or _RiskTier("low")
        self.requires_confirmation = requires_confirmation


class _RiskTier:
    def __init__(self, value: str = "low") -> None:
        self.value = value


class IntentRouter:
    def __init__(self) -> None:
        pass

    def route(self, text: str, **kwargs: Any) -> IntentRoute:
        text_lower = text.lower()
        if any(kw in text_lower for kw in ("scan", "nmap", "port scan")):
            return IntentRoute(mode="scan", risk_tier=_RiskTier("medium"))
        if any(kw in text_lower for kw in ("recon", "enumerate", "discover")):
            return IntentRoute(mode="recon", risk_tier=_RiskTier("low"))
        if any(kw in text_lower for kw in ("web", "http", "nikto", "nuclei")):
            return IntentRoute(mode="web", risk_tier=_RiskTier("medium"))
        if any(kw in text_lower for kw in ("brute", "crack", "password")):
            return IntentRoute(mode="brute", risk_tier=_RiskTier("high"), requires_confirmation=True)
        return IntentRoute(mode="general", risk_tier=_RiskTier("low"))


class SessionKernel:
    def __init__(self) -> None:
        self._context: dict[str, Any] = {}
        self._sessions: dict[str, dict[str, Any]] = {}

    def get(self, key: str) -> Any:
        return self._context.get(key)

    def set(self, key: str, value: Any) -> None:
        self._context[key] = value

    def clear(self) -> None:
        self._context.clear()

    def start(self, **kwargs: Any) -> dict[str, Any]:
        import uuid
        session_id = str(uuid.uuid4())[:8]
        session = {"id": session_id, **kwargs}
        self._sessions[session_id] = session
        return session

    def add_operation(self, **kwargs: Any) -> dict[str, Any]:
        return {"id": str(__import__("uuid").uuid4())[:8], **kwargs}
