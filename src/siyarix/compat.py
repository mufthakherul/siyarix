# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backward-compatible wrappers for old module names."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ExecutionMode(StrEnum):
    REGISTRY = "registry"
    AUTONOMOUS = "autonomous"
    INTEGRATED = "integrated"


class ExecutionEngine:
    def __init__(self, mode: ExecutionMode = ExecutionMode.INTEGRATED,
                 registry: Any = None, config: dict[str, Any] | None = None) -> None:
        self._mode = mode
        self._registry = registry
        self._config = config or {}

    async def execute(self, goal: str, **kwargs: Any) -> dict[str, Any]:
        from .core import AgentCore, AgentMode, AgentGoal
        mode_map = {
            ExecutionMode.REGISTRY: AgentMode.REGISTRY,
            ExecutionMode.AUTONOMOUS: AgentMode.AUTONOMOUS,
            ExecutionMode.INTEGRATED: AgentMode.HYBRID,
        }
        agent = AgentCore(mode=mode_map.get(self._mode, AgentMode.HYBRID))
        await agent.initialize()
        agent_goal = AgentGoal(description=goal, **kwargs)
        result = await agent.execute_goal(agent_goal)
        return {"success": result.success, "summary": result.summary, "findings": result.findings}

    async def run(self, goal: str, **kwargs: Any) -> dict[str, Any]:
        return await self.execute(goal, **kwargs)


class IntentRouter:
    def __init__(self) -> None:
        pass

    def route(self, text: str) -> str:
        text_lower = text.lower()
        if any(kw in text_lower for kw in ("scan", "nmap", "port scan")):
            return "scan"
        if any(kw in text_lower for kw in ("recon", "enumerate", "discover")):
            return "recon"
        if any(kw in text_lower for kw in ("web", "http", "nikto", "nuclei")):
            return "web"
        if any(kw in text_lower for kw in ("brute", "crack", "password")):
            return "brute"
        return "general"


class SessionKernel:
    def __init__(self) -> None:
        self._context: dict[str, Any] = {}

    def get(self, key: str) -> Any:
        return self._context.get(key)

    def set(self, key: str, value: Any) -> None:
        self._context[key] = value

    def clear(self) -> None:
        self._context.clear()
