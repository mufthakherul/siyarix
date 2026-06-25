# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool registry with capability graph and dynamic discovery.

Supports both curated security-tool metadata and arbitrary-PATH-executable
discovery, with a generic fallback handler for unknown tools."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .parsers import ParserRegistry

from .events import Event, EventType, emit_sync
from .exceptions import (
    PermissionDeniedError,
    ToolExecutionError,
    ToolNotFoundError,
)

# Expose models, graph, handlers, and metadata via the registry module
from .tool_models import (
    ToolHandler,
    ToolCategory,
    RiskLevel,
    ToolCapability,
    _cached_which,
)
from .tool_graph import ToolCapabilityGraph
from .tool_metadata import (
    categorize_tool,
    risk_for_tool,
    describe_tool,
    tags_for_tool,
)
from .tool_version import get_tool_metadata

from .tool_handlers import (
    make_nmap_handler,
    make_web_handler,
    make_portscan_handler,
    make_recon_handler,
    make_brute_handler,
    make_network_handler,
    make_crypto_handler,
    make_curl_handler,
    make_dns_handler,
    make_whois_handler,
    make_generic_handler,
)

from .internal_tools import (
    make_graph_analyzer_handler,
    make_threat_intel_handler,
)

logger = logging.getLogger(__name__)

# Class-level handler map for curated security tools
_HANDLER_MAP: dict[str, Any] = {
    "nmap": make_nmap_handler,
    "nikto": make_web_handler,
    "nuclei": make_web_handler,
    "gobuster": make_web_handler,
    "ffuf": make_web_handler,
    "hydra": make_brute_handler,
    "masscan": make_portscan_handler,
    "amass": make_recon_handler,
    "subfinder": make_recon_handler,
    "wpscan": make_web_handler,
    "sqlmap": make_web_handler,
    "shodan": make_recon_handler,
    "bettercap": make_network_handler,
    "ettercap": make_network_handler,
    "aircrack-ng": make_network_handler,
    "hashcat": make_crypto_handler,
    "john": make_crypto_handler,
    "burpsuite": make_web_handler,
    "zaproxy": make_web_handler,
    "whatweb": make_web_handler,
    "curl": make_curl_handler,
    "wget": make_curl_handler,
    "dig": make_dns_handler,
    "whois": make_whois_handler,
    "graph_analyzer": make_graph_analyzer_handler,
    "threat_intel": make_threat_intel_handler,
}

_CURATED_TOOL_NAMES: tuple[str, ...] = (
    "nmap",
    "nikto",
    "nuclei",
    "gobuster",
    "ffuf",
    "hydra",
    "masscan",
    "amass",
    "subfinder",
    "wpscan",
    "sqlmap",
    "shodan",
    "bettercap",
    "ettercap",
    "aircrack-ng",
    "hashcat",
    "john",
    "burpsuite",
    "zaproxy",
    "whatweb",
    "curl",
    "wget",
    "dig",
    "whois",
    "graph_analyzer",
    "threat_intel",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "b2sum",
    "cksum",
    "ls",
    "date",
    "df",
    "free",
    "who",
    "uptime",
    "top",
    "acpi",
    "ps",
    "uname",
    "cat",
    "tail",
    "head",
    "wc",
    "grep",
    "sort",
    "env",
    "id",
    "hostname",
)

_INTERPRETER_NAMES: tuple[str, ...] = (
    "python3",
    "python",
    "node",
    "go",
    "rustc",
    "gcc",
    "g++",
    "java",
    "ruby",
    "bash",
)

_BLACKLISTED_PATH_TOOLS: frozenset[str] = frozenset(
    {
        "conhost.exe",
        "sihost.exe",
        "taskhostw.exe",
        "svchost.exe",
        "RuntimeBroker.exe",
        "securityhealthsystray.exe",
    }
)


class ToolRegistry:
    def __init__(self, permission_gate: Any = None) -> None:
        self._graph = ToolCapabilityGraph()
        self._handlers: dict[str, ToolHandler] = {}
        from .parsers import ParserRegistry

        self._parser_registry = ParserRegistry()
        self._loaded = False
        self._load_count = 0
        self._permission_gate = permission_gate
        self._event_bus = None
        self._lock = threading.Lock()

    @property
    def graph(self) -> ToolCapabilityGraph:
        return self._graph

    @property
    def parser_registry(self) -> ParserRegistry:
        return self._parser_registry

    def register(self, tool: ToolCapability, handler: ToolHandler | None = None) -> None:
        with self._lock:
            existing = self._graph.get_tool(tool.name)
            if existing:
                tool.usage_count = existing.usage_count
                tool.last_used = existing.last_used
                tool.avg_duration_ms = existing.avg_duration_ms
            self._graph.add_tool(tool)
            if handler:
                self._handlers[tool.name] = handler
        emit_sync(
            Event(type=EventType.TOOL_REGISTERED, source="registry", data={"tool": tool.name})
        )

    def register_many(self, tools: list[tuple[ToolCapability, ToolHandler | None]]) -> int:
        for tool, handler in tools:
            self.register(tool, handler)
        return len(tools)

    def unregister(self, name: str) -> bool:
        with self._lock:
            removed = self._graph._nodes.pop(name, None)
            self._handlers.pop(name, None)
        if removed:
            emit_sync(
                Event(type=EventType.TOOL_UNREGISTERED, source="registry", data={"tool": name})
            )
            return True
        return False

    def unregister_many(self, names: list[str]) -> int:
        count = 0
        for name in names:
            if self.unregister(name):
                count += 1
        return count

    def get_handler(self, name: str) -> ToolHandler | None:
        return self._handlers.get(name)

    async def execute(self, name: str, **kwargs: Any) -> dict[str, Any]:
        with self._lock:
            tool = self._graph.get_tool(name)
            handler = self._handlers.get(name)
        if not tool:
            raise ToolNotFoundError(f"Tool not found: {name}")
        if not handler:
            raise ToolNotFoundError(f"No handler registered for: {name}")

        if tool.availability:
            from .tool_availability import ToolAvailabilityContext, evaluate_availability

            ctx = ToolAvailabilityContext()
            avail = evaluate_availability(tool.availability, ctx)
            if not avail.available:
                reasons = "; ".join(d.detail for d in avail.diagnostics)
                raise ToolNotFoundError(f"Tool {name} unavailable: {reasons}")

        if self._permission_gate:
            command = kwargs.get("command", "")
            if command:
                gate_result = self._permission_gate.check(command, tool=name)
                if not gate_result.allowed:
                    raise PermissionDeniedError(gate_result.reason)
                if gate_result.requires_review:
                    from .shell_review import review_and_confirm

                    reviewed = review_and_confirm(command, name, gate_result.reason)
                    if reviewed is None:
                        raise PermissionDeniedError(f"Cancelled by user: {gate_result.reason}")

        start = time.monotonic()
        try:
            result = await handler(**kwargs)
            result.setdefault("status", "success")
            result.setdefault("tool", name)
            output = result.get("output", "")
            if output and self._parser_registry.has_parser(name):
                parsed = self._parser_registry.parse(name, output)
                if parsed:
                    result["findings"] = parsed
            duration = (time.monotonic() - start) * 1000
            if tool:
                import asyncio

                def _update_stats() -> None:
                    with self._lock:
                        tool.usage_count += 1
                        tool.last_used = time.time()
                        tool.avg_duration_ms = (
                            tool.avg_duration_ms * (tool.usage_count - 1) + duration
                        ) / tool.usage_count

                await asyncio.to_thread(_update_stats)
            return result
        except (PermissionDeniedError, ToolNotFoundError):
            raise
        except Exception as e:
            raise ToolExecutionError(f"Tool {name} execution failed: {e}") from e

    def _build_tool_capability(
        self, name: str, binary: str, version: str, handler_factory: Any = None
    ) -> tuple[ToolCapability, ToolHandler | None]:
        has_parser = self._parser_registry.has_parser(name)
        meta = get_tool_metadata(name)
        personas = meta.get("personas", []) if meta else []
        return (
            ToolCapability(
                name=name,
                binary=binary,
                installed=True,
                version=version,
                category=categorize_tool(name),
                risk_level=risk_for_tool(name),
                description=describe_tool(name),
                tags=tags_for_tool(name),
                parser=name if has_parser else "",
                metadata={"personas": personas} if personas else {},
            ),
            handler_factory(name) if handler_factory else make_generic_handler(name),
        )

    def discover_from_path(self) -> int:
        self._parser_registry.discover()
        count = 0
        tools_to_register: list[tuple[ToolCapability, ToolHandler | None]] = []

        for name in _CURATED_TOOL_NAMES:
            binary = _cached_which(name)
            if binary:
                handler_factory = _HANDLER_MAP.get(name)
                cap, handler = self._build_tool_capability(name, binary, "", handler_factory)
                tools_to_register.append((cap, handler))
                count += 1

        for name in _INTERPRETER_NAMES:
            binary = _cached_which(name)
            if binary:
                tools_to_register.append(
                    (
                        ToolCapability(
                            name=name,
                            binary=name,
                            installed=True,
                            version="",
                            category=ToolCategory.UTILITY,
                            risk_level=RiskLevel.SAFE,
                            description=f"{name} interpreter/compiler",
                            tags=["language", name],
                        ),
                        None,
                    )
                )
                count += 1

        if tools_to_register:
            self.register_many(tools_to_register)

        self._loaded = True
        self._load_count += 1
        emit_sync(Event(type=EventType.TOOL_REGISTERED, source="registry", data={"count": count}))
        return count

    def update_metadata(self, output_path: Path) -> int:
        """Scan PATH and write tool metadata to a JSON file, returning the count."""
        self.discover_from_path()
        self.scan_path()
        tools = self.list_tools()
        data: dict[str, Any] = {}
        for t in tools:
            data[t.name] = {
                "name": t.name,
                "description": t.description,
                "category": t.category.value if hasattr(t.category, "value") else str(t.category),
                "risk_level": t.risk_level.value
                if hasattr(t.risk_level, "value")
                else str(t.risk_level),
                "binary": t.binary,
                "installed": t.installed,
                "tags": t.tags,
                "version": t.version,
            }
        output_path.write_text(json.dumps(data, indent=2, default=str))
        return len(tools)

    def register_handler(self, name: str, handler: ToolHandler) -> None:
        """Register (or override) a handler for a given tool."""
        with self._lock:
            self._handlers[name] = handler

    def scan_path(self) -> int:
        """Discover *every* executable on ``$PATH`` and register it.

        Tools that already have a custom handler keep their handler;
        everything else gets ``make_generic_handler`` which simply
        passes the call arguments as CLI flags.

        Returns the number of newly registered tools.
        """
        count = 0
        seen: set[str] = set()
        tools_to_register: list[tuple[ToolCapability, ToolHandler | None]] = []
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)

        for path_dir in path_dirs:
            if not path_dir:
                continue
            try:
                for entry in os.listdir(path_dir):
                    if entry in seen or entry in _BLACKLISTED_PATH_TOOLS:
                        continue
                    seen.add(entry)
                    full = os.path.join(path_dir, entry)
                    if os.name == "nt":
                        if not (
                            os.path.isfile(full)
                            and full.lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".com"))
                        ):
                            continue
                    elif not (os.path.isfile(full) and os.access(full, os.X_OK)):
                        continue
                    if self._graph.get_tool(entry):
                        continue
                    meta = get_tool_metadata(entry)
                    personas = meta.get("personas", []) if meta else []
                    category = (
                        ToolCategory(meta["category"])
                        if meta and "category" in meta
                        else categorize_tool(entry)
                    )
                    if category == ToolCategory.UTILITY and not personas and not meta:
                        continue
                    tools_to_register.append(
                        (
                            ToolCapability(
                                name=entry,
                                binary=entry,
                                installed=True,
                                version="",
                                category=category,
                                risk_level=(
                                    RiskLevel(meta["risk_level"])
                                    if meta and "risk_level" in meta
                                    else RiskLevel.LOW
                                ),
                                description=describe_tool(entry),
                                tags=tags_for_tool(entry),
                                metadata={"personas": personas} if personas else {},
                            ),
                            make_generic_handler(entry),
                        )
                    )
                    count += 1
            except OSError as e:
                logger.debug("Failed to scan directory %s: %s", path_dir, e)
                continue

        if tools_to_register:
            self.register_many(tools_to_register)

        self._loaded = True
        return count

    def load_from_json(self, path: Path, register_handlers: bool = True) -> int:
        count = 0
        if not path.exists():
            return count
        try:
            data = json.loads(path.read_text())
            tools_to_register: list[tuple[ToolCapability, ToolHandler | None]] = []
            for name, info in data.items():
                handler_factory = _HANDLER_MAP.get(name)
                handler = handler_factory(name) if handler_factory and register_handlers else None
                meta = info if isinstance(info, dict) else {}
                tools_to_register.append(
                    (
                        ToolCapability(
                            name=name,
                            description=meta.get("description", ""),
                            category=ToolCategory(meta.get("category", "utility")),
                            risk_level=RiskLevel(meta.get("risk_level", "safe")),
                            aliases=meta.get("aliases", []),
                            tags=meta.get("tags", []),
                            binary=meta.get("binary", ""),
                            version=meta.get("version", ""),
                            installed=meta.get("installed", False),
                            parser=meta.get("parser", ""),
                        ),
                        handler,
                    )
                )
                count += 1
            if tools_to_register:
                self.register_many(tools_to_register)
        except Exception:
            logger.exception("Failed to load tool registry from %s", path)
        return count

    def load_custom_tools(self) -> int:
        from .config import get_config_dir

        custom_tools_path = get_config_dir() / "custom_tools.json"
        if not custom_tools_path.exists():
            return 0
        try:
            data = json.loads(custom_tools_path.read_text(encoding="utf-8"))
            tools_to_register: list[tuple[ToolCapability, ToolHandler | None]] = []
            for name, meta in data.items():
                tools_to_register.append(
                    (
                        ToolCapability(
                            name=name,
                            description=meta.get("description", "Custom tool"),
                            category=ToolCategory(meta.get("category", "utility")),
                            risk_level=RiskLevel(meta.get("risk_level", "low")),
                            aliases=meta.get("aliases", []),
                            tags=meta.get("tags", ["custom"]),
                            binary=meta.get("binary", name),
                            version=meta.get("version", "custom"),
                            installed=True,
                            parser=meta.get("parser", ""),
                        ),
                        make_generic_handler(name),
                    )
                )
            if tools_to_register:
                self.register_many(tools_to_register)
                logger.info(
                    f"Loaded {len(tools_to_register)} custom tools from {custom_tools_path}"
                )
            return len(tools_to_register)
        except Exception:
            logger.exception("Failed to load custom tools from %s", custom_tools_path)
            return 0

    def list_tools(
        self,
        category: ToolCategory | None = None,
        available_only: bool = False,
        tags: list[str] | None = None,
        search: str | None = None,
    ) -> list[ToolCapability]:
        if category:
            tools = self._graph.get_tools_by_category(category)
        else:
            tools = self._graph.all_tools()
        if available_only:
            tools = [t for t in tools if t.is_available]
        if tags:
            tag_set = set(t.lower() for t in tags)
            tools = [t for t in tools if tag_set.intersection(t.tags)]
        if search:
            search_lower = search.lower()
            tools = [
                t
                for t in tools
                if search_lower in t.name.lower()
                or search_lower in t.description.lower()
                or any(search_lower in tag.lower() for tag in t.tags)
                or any(search_lower in alias.lower() for alias in getattr(t, "aliases", []))
            ]
        return sorted(tools, key=lambda t: t.name)

    def search(self, query: str, top_k: int = 10) -> list[ToolCapability]:
        return self._graph.find_optimal_tools(query)[:top_k]

    def get_tool_alternatives(self, name: str) -> list[str]:
        tool = self._graph.get_tool(name)
        if tool and tool.related_tools:
            return tool.related_tools
        from .planner_registry import TOOL_ALTERNATIVES

        return TOOL_ALTERNATIVES.get(name, [])

    def get_by_tags(self, tags: list[str]) -> list[ToolCapability]:
        tag_set = set(t.lower() for t in tags)
        return [t for t in self._graph.all_tools() if tag_set.intersection(t.tags)]

    def get_popular_tools(self, top_n: int = 5) -> list[ToolCapability]:
        tools = [t for t in self._graph.all_tools() if t.usage_count > 0]
        return sorted(tools, key=lambda t: -t.usage_count)[:top_n]

    def stats(self) -> dict[str, Any]:
        all_tools = self._graph.all_tools()
        available = [t for t in all_tools if t.is_available]
        category_counts: dict[str, int] = {}
        for t in all_tools:
            cat = t.category.value if hasattr(t.category, "value") else str(t.category)
            category_counts[cat] = category_counts.get(cat, 0) + 1
        return {
            "total": len(all_tools),
            "available": len(available),
            "categories": len(set(t.category for t in all_tools)),
            "handlers": len(self._handlers),
            "parsers": self._parser_registry.count,
            "loaded": self._loaded,
            "load_count": self._load_count,
            "category_counts": category_counts,
        }
