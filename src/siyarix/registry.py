# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool registry with capability graph and dynamic discovery.

Supports both curated security-tool metadata and arbitrary-PATH-executable
discovery, with a generic fallback handler for unknown tools."""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from .events import Event, EventType, emit_sync
from .exceptions import PermissionDeniedError
from .parsers import ParserRegistry

# Expose models, graph, handlers, and metadata via the registry module
from .tool_models import (
    ToolHandler,
    ToolCategory,
    RiskLevel,
    ToolCapability,
)
from .tool_graph import ToolCapabilityGraph
from .tool_metadata import (
    categorize_tool,
    risk_for_tool,
    describe_tool,
    tags_for_tool,
)
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

logger = logging.getLogger(__name__)


class ToolRegistry:
    def __init__(self, permission_gate: Any = None) -> None:
        self._graph = ToolCapabilityGraph()
        self._handlers: dict[str, ToolHandler] = {}
        self._parser_registry = ParserRegistry()
        self._loaded = False
        self._permission_gate = permission_gate

    @property
    def graph(self) -> ToolCapabilityGraph:
        return self._graph

    @property
    def parser_registry(self) -> ParserRegistry:
        return self._parser_registry

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

        # ── Availability check ──
        if tool.availability:
            from .tool_availability import ToolAvailabilityContext, evaluate_availability
            ctx = ToolAvailabilityContext()
            avail = evaluate_availability(tool.availability, ctx)
            if not avail.available:
                reasons = "; ".join(d.detail for d in avail.diagnostics)
                return {"status": "error", "error": f"Tool {name} unavailable: {reasons}"}

        # ── Permission gate ──
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

        try:
            result = await handler(**kwargs)
            result.setdefault("status", "success")
            result.setdefault("tool", name)
            output = result.get("output", "")
            if output and self._parser_registry.has_parser(name):
                parsed = self._parser_registry.parse(name, output)
                if parsed:
                    result["findings"] = parsed
            return result
        except PermissionDeniedError:
            raise
        except Exception as e:
            logger.exception("Tool execution failed: %s", name)
            return {"status": "error", "error": str(e), "tool": name}

    def discover_from_path(self) -> int:
        self._parser_registry.discover()
        count = 0
        _handler_map = {
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
        }
        for name in (
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
        ):
            binary = shutil.which(name)
            if binary:
                handler_factory = _handler_map.get(name)
                has_parser = self._parser_registry.has_parser(name)
                self.register(
                    ToolCapability(
                        name=name,
                        binary=name,
                        installed=True,
                        category=categorize_tool(name),
                        risk_level=risk_for_tool(name),
                        description=describe_tool(name),
                        tags=tags_for_tool(name),
                        parser=name if has_parser else "",
                    ),
                    handler=handler_factory(name) if handler_factory else None,
                )
                count += 1
        for name in (
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
        ):
            binary = shutil.which(name)
            if binary:
                self.register(
                    ToolCapability(
                        name=name,
                        binary=name,
                        installed=True,
                        category=ToolCategory.UTILITY,
                        risk_level=RiskLevel.SAFE,
                        description=f"{name} interpreter/compiler",
                        tags=["language", name],
                    )
                )
                count += 1
        self._loaded = True
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
            }
        output_path.write_text(json.dumps(data, indent=2))
        return len(tools)

    def register_handler(self, name: str, handler: ToolHandler) -> None:
        """Register (or override) a handler for a given tool."""
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
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            if not path_dir:
                continue
            try:
                for entry in os.listdir(path_dir):
                    if entry in seen:
                        continue
                    seen.add(entry)
                    full = os.path.join(path_dir, entry)
                    if os.name == "nt":
                        # On Windows os.X_OK is True for most files; filter by executable extensions
                        if not (
                            os.path.isfile(full)
                            and full.endswith((".exe", ".bat", ".cmd", ".ps1", ".com"))
                        ):
                            continue
                    elif not (os.path.isfile(full) and os.access(full, os.X_OK)):
                        continue
                    if self._graph.get_tool(entry):
                        continue  # already registered
                    self.register(
                        ToolCapability(
                            name=entry,
                            binary=entry,
                            installed=True,
                            category=ToolCategory.UTILITY,
                            risk_level=RiskLevel.LOW,
                            description=describe_tool(entry),
                            tags=tags_for_tool(entry),
                        ),
                        handler=make_generic_handler(entry),
                    )
                    count += 1
            except OSError:
                continue
        self._loaded = True
        return count

    def load_from_json(self, path: Path) -> int:
        count = 0
        if not path.exists():
            return count
        try:
            data = json.loads(path.read_text())
            for name, info in data.items():
                self.register(
                    ToolCapability(
                        name=name,
                        description=info.get("description", ""),
                        category=ToolCategory(info.get("category", "utility")),
                        risk_level=RiskLevel(info.get("risk_level", "safe")),
                        aliases=info.get("aliases", []),
                        tags=info.get("tags", []),
                        binary=info.get("binary", ""),
                        installed=info.get("installed", False),
                    )
                )
                count += 1
        except Exception:
            logger.exception("Failed to load tool registry from %s", path)
        return count

    def list_tools(
        self, category: ToolCategory | None = None, available_only: bool = False
    ) -> list[ToolCapability]:
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
