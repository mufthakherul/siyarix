# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capability graph for resolving tool chains and similarities."""

from __future__ import annotations

from .tool_models import ToolCapability, ToolCategory, ToolEdge


class ToolCapabilityGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, ToolCapability] = {}
        self._edges: list[ToolEdge] = []
        self._alias_map: dict[str, str] = {}

    def add_tool(self, tool: ToolCapability) -> None:
        self._nodes[tool.name] = tool
        for alias in tool.aliases:
            self._alias_map[alias] = tool.name

    def add_edge(self, edge: ToolEdge) -> None:
        self._edges.append(edge)

    def get_tool(self, name: str) -> ToolCapability | None:
        if name in self._nodes:
            return self._nodes[name]
        canonical = self._alias_map.get(name)
        if canonical:
            return self._nodes.get(canonical)
        return None

    def get_tools_by_category(self, category: ToolCategory) -> list[ToolCapability]:
        return [t for t in self._nodes.values() if t.category == category]

    def get_available_tools(self) -> list[ToolCapability]:
        return [t for t in self._nodes.values() if t.is_available]

    def get_chain(self, start: str, goal: str) -> list[str]:
        if start not in self._nodes or goal not in self._nodes:
            return []
        visited: set[str] = set()
        queue: list[list[str]] = [[start]]
        while queue:
            path = queue.pop(0)
            current = path[-1]
            if current == goal:
                return path
            if current in visited:
                continue
            visited.add(current)
            for edge in self._edges:
                if edge.source == current and edge.target not in visited:
                    queue.append(path + [edge.target])
                elif edge.target == current and edge.source not in visited:
                    queue.append(path + [edge.source])
        return []

    def find_optimal_tools(
        self, goal: str, available: list[str] | None = None
    ) -> list[ToolCapability]:
        goal_lower = goal.lower()
        scored: list[tuple[float, ToolCapability]] = []
        for tool in self._nodes.values():
            if available and tool.name not in available:
                continue
            score = 0.0
            if goal_lower in tool.name.lower():
                score += 10.0
            for tag in tool.tags:
                if goal_lower in tag.lower():
                    score += 3.0
            if goal_lower in tool.description.lower():
                score += 2.0
            if tool.is_available:
                score += 1.0
            if score > 0:
                scored.append((score, tool))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored]

    def all_tools(self) -> list[ToolCapability]:
        return list(self._nodes.values())

__all__ = [
    "ToolCapabilityGraph",
]
