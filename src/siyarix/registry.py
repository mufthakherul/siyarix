# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool registry with capability graph and dynamic discovery."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

ToolHandler = Callable[..., Coroutine[Any, Any, dict[str, Any]]]


class ToolCategory(StrEnum):
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"
    UTILITY = "utility"
    NETWORK = "network"
    WEB = "web"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    CONTAINER = "container"
    CLOUD = "cloud"


class RiskLevel(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolCapability:
    name: str
    description: str = ""
    category: ToolCategory = ToolCategory.UTILITY
    risk_level: RiskLevel = RiskLevel.SAFE
    aliases: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    inputs: dict[str, str] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    related_tools: list[str] = field(default_factory=list)
    workflows: list[str] = field(default_factory=list)
    binary: str = ""
    version: str = ""
    installed: bool = False
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_available(self) -> bool:
        if not self.installed and self.binary:
            return shutil.which(self.binary) is not None
        return self.installed


@dataclass
class ToolEdge:
    source: str
    target: str
    relation: str = "chain"
    weight: float = 1.0


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

    def find_optimal_tools(self, goal: str, available: list[str] | None = None) -> list[ToolCapability]:
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


class ToolRegistry:
    def __init__(self) -> None:
        self._graph = ToolCapabilityGraph()
        self._handlers: dict[str, ToolHandler] = {}
        self._loaded = False

    @property
    def graph(self) -> ToolCapabilityGraph:
        return self._graph

    def register(self, tool: ToolCapability, handler: ToolHandler | None = None) -> None:
        self._graph.add_tool(tool)
        if handler:
            self._handlers[tool.name] = handler

    def unregister(self, name: str) -> None:
        self._graph._nodes.pop(name, None)
        self._handlers.pop(name, None)

    def get_handler(self, name: str) -> ToolHandler | None:
        return self._handlers.get(name)

    async def execute(self, name: str, **kwargs: Any) -> dict[str, Any]:
        tool = self._graph.get_tool(name)
        if not tool:
            return {"status": "error", "error": f"Tool not found: {name}"}
        handler = self._handlers.get(name)
        if not handler:
            return {"status": "error", "error": f"No handler for: {name}"}
        try:
            result = await handler(**kwargs)
            result.setdefault("status", "success")
            result.setdefault("tool", name)
            return result
        except Exception as e:
            logger.exception("Tool execution failed: %s", name)
            return {"status": "error", "error": str(e), "tool": name}

    def discover_from_path(self) -> int:
        count = 0
        for name in ("nmap", "nikto", "nuclei", "gobuster", "ffuf", "hydra", "masscan",
                      "amass", "subfinder", "wpscan", "sqlmap", "shodan", "bettercap",
                      "ettercap", "aircrack-ng", "hashcat", "john", "burpsuite", "zaproxy"):
            binary = shutil.which(name)
            if binary:
                self.register(ToolCapability(
                    name=name, binary=name, installed=True,
                    category=_categorize_tool(name),
                    risk_level=_risk_for_tool(name),
                    description=_describe_tool(name),
                    tags=_tags_for_tool(name),
                ))
                count += 1
        for name in ("python3", "python", "node", "go", "rustc", "gcc", "g++", "java", "ruby", "bash"):
            binary = shutil.which(name)
            if binary:
                self.register(ToolCapability(
                    name=name, binary=name, installed=True,
                    category=ToolCategory.UTILITY,
                    risk_level=RiskLevel.SAFE,
                    description=f"{name} interpreter/compiler",
                    tags=["language", name],
                ))
                count += 1
        self._loaded = True
        return count

    def load_from_json(self, path: Path) -> int:
        count = 0
        if not path.exists():
            return count
        try:
            data = json.loads(path.read_text())
            for name, info in data.items():
                self.register(ToolCapability(
                    name=name, description=info.get("description", ""),
                    category=ToolCategory(info.get("category", "utility")),
                    risk_level=RiskLevel(info.get("risk_level", "safe")),
                    aliases=info.get("aliases", []),
                    tags=info.get("tags", []),
                    binary=info.get("binary", ""),
                    installed=info.get("installed", False),
                ))
                count += 1
        except Exception:
            logger.exception("Failed to load tool registry from %s", path)
        return count

    def list_tools(self, category: ToolCategory | None = None, available_only: bool = False) -> list[ToolCapability]:
        if category:
            tools = self._graph.get_tools_by_category(category)
        else:
            tools = self._graph.all_tools()
        if available_only:
            tools = [t for t in tools if t.is_available]
        return sorted(tools, key=lambda t: t.name)

    def search(self, query: str) -> list[ToolCapability]:
        return self._graph.find_optimal_tools(query)

    def stats(self) -> dict[str, Any]:
        all_tools = self._graph.all_tools()
        return {
            "total": len(all_tools),
            "available": len([t for t in all_tools if t.is_available]),
            "categories": len(set(t.category for t in all_tools)),
            "loaded": self._loaded,
        }


def _categorize_tool(name: str) -> ToolCategory:
    mapping = {
        "nmap": ToolCategory.RECON, "masscan": ToolCategory.RECON,
        "amass": ToolCategory.RECON, "subfinder": ToolCategory.RECON,
        "shodan": ToolCategory.RECON, "bettercap": ToolCategory.NETWORK,
        "ettercap": ToolCategory.NETWORK,
        "nikto": ToolCategory.SCANNING, "nuclei": ToolCategory.SCANNING,
        "wpscan": ToolCategory.SCANNING, "sqlmap": ToolCategory.SCANNING,
        "gobuster": ToolCategory.SCANNING, "ffuf": ToolCategory.SCANNING,
        "hydra": ToolCategory.EXPLOITATION,
        "hashcat": ToolCategory.CRYPTO, "john": ToolCategory.CRYPTO,
        "aircrack-ng": ToolCategory.NETWORK,
        "burpsuite": ToolCategory.WEB, "zaproxy": ToolCategory.WEB,
    }
    return mapping.get(name, ToolCategory.UTILITY)


def _risk_for_tool(name: str) -> RiskLevel:
    high_risk = {"metasploit", "sqlmap", "hashcat", "hydra", "ettercap", "bettercap"}
    medium_risk = {"nmap", "nuclei", "nikto", "gobuster", "ffuf", "wpscan", "masscan"}
    if name in high_risk:
        return RiskLevel.HIGH
    if name in medium_risk:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _describe_tool(name: str) -> str:
    descriptions = {
        "nmap": "Network port scanner and service detector",
        "nikto": "Web server vulnerability scanner",
        "nuclei": "Template-based vulnerability scanner",
        "gobuster": "Directory/file & DNS busting tool",
        "ffuf": "Fast web fuzzer",
        "hydra": "Network login brute-forcer",
        "masscan": "TCP port scanner at scale",
        "amass": "Attack surface mapping and asset discovery",
        "subfinder": "Subdomain discovery tool",
        "wpscan": "WordPress security scanner",
        "sqlmap": "SQL injection detection and exploitation",
        "shodan": "Internet-connected device search engine",
        "bettercap": "Network attack and monitoring framework",
        "ettercap": "ARP poisoning and MITM attacks",
        "aircrack-ng": "WiFi network security assessment",
        "hashcat": "Password hash recovery",
        "john": "Password cracker",
        "burpsuite": "Web application security testing",
        "zaproxy": "Web application security scanner",
    }
    return descriptions.get(name, name)


def _tags_for_tool(name: str) -> list[str]:
    tag_map = {
        "nmap": ["port-scan", "network", "service-detection"],
        "nikto": ["web", "vulnerability", "server"],
        "nuclei": ["vulnerability", "template", "http"],
        "gobuster": ["directory", "brute-force", "http"],
        "ffuf": ["fuzzer", "directory", "http"],
        "hydra": ["brute-force", "login", "network"],
        "masscan": ["port-scan", "fast", "network"],
        "amass": ["recon", "subdomain", "osint"],
        "subfinder": ["recon", "subdomain", "passive"],
        "wpscan": ["cms", "wordpress", "vulnerability"],
        "sqlmap": ["sql-injection", "database", "exploit"],
        "shodan": ["osint", "iot", "search"],
        "bettercap": ["mitm", "arp", "sniffing"],
        "ettercap": ["mitm", "arp", "poisoning"],
        "aircrack-ng": ["wifi", "wpa", "capture"],
        "hashcat": ["password", "hash", "gpu"],
        "john": ["password", "hash", "crack"],
        "burpsuite": ["proxy", "web", "scan"],
        "zaproxy": ["proxy", "web", "scan"],
    }
    return tag_map.get(name, [name])
