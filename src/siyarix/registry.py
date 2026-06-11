# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool registry with capability graph and dynamic discovery.

Supports both curated security-tool metadata and arbitrary-PATH-executable
discovery, with a generic fallback handler for unknown tools."""

from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Coroutine

from .events import Event, EventType, emit_sync
from .exceptions import PermissionDeniedError
from .parsers import ParserRegistry

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
    parser: str = ""
    availability: dict[str, Any] | None = None

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
            "nmap": _make_nmap_handler,
            "nikto": _make_web_handler,
            "nuclei": _make_web_handler,
            "gobuster": _make_web_handler,
            "ffuf": _make_web_handler,
            "hydra": _make_brute_handler,
            "masscan": _make_portscan_handler,
            "amass": _make_recon_handler,
            "subfinder": _make_recon_handler,
            "wpscan": _make_web_handler,
            "sqlmap": _make_web_handler,
            "shodan": _make_recon_handler,
            "bettercap": _make_network_handler,
            "ettercap": _make_network_handler,
            "aircrack-ng": _make_network_handler,
            "hashcat": _make_crypto_handler,
            "john": _make_crypto_handler,
            "burpsuite": _make_web_handler,
            "zaproxy": _make_web_handler,
            "whatweb": _make_web_handler,
            "curl": _make_curl_handler,
            "wget": _make_curl_handler,
            "dig": _make_dns_handler,
            "whois": _make_whois_handler,
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
                        category=_categorize_tool(name),
                        risk_level=_risk_for_tool(name),
                        description=_describe_tool(name),
                        tags=_tags_for_tool(name),
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
        everything else gets ``_make_generic_handler`` which simply
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
                            description=_describe_tool(entry),
                            tags=_tags_for_tool(entry),
                        ),
                        handler=_make_generic_handler(entry),
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


def _categorize_tool(name: str) -> ToolCategory:
    mapping = {
        "nmap": ToolCategory.RECON,
        "masscan": ToolCategory.RECON,
        "amass": ToolCategory.RECON,
        "subfinder": ToolCategory.RECON,
        "shodan": ToolCategory.RECON,
        "bettercap": ToolCategory.NETWORK,
        "ettercap": ToolCategory.NETWORK,
        "nikto": ToolCategory.SCANNING,
        "nuclei": ToolCategory.SCANNING,
        "wpscan": ToolCategory.SCANNING,
        "sqlmap": ToolCategory.SCANNING,
        "gobuster": ToolCategory.SCANNING,
        "ffuf": ToolCategory.SCANNING,
        "hydra": ToolCategory.EXPLOITATION,
        "hashcat": ToolCategory.CRYPTO,
        "john": ToolCategory.CRYPTO,
        "aircrack-ng": ToolCategory.NETWORK,
        "burpsuite": ToolCategory.WEB,
        "zaproxy": ToolCategory.WEB,
        "dig": ToolCategory.RECON,
        "whois": ToolCategory.RECON,
        "curl": ToolCategory.UTILITY,
        "whatweb": ToolCategory.WEB,
        "wget": ToolCategory.UTILITY,
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
        "dig": "DNS record query and enumeration tool",
        "whois": "Domain registration and WHOIS lookup",
        "curl": "HTTP client for headers and response analysis",
        "whatweb": "Web technology stack fingerprinting",
        "wget": "HTTP/HTTPS file download and mirroring",
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
        "dig": ["dns", "recon", "enumeration"],
        "whois": ["osint", "recon", "registration"],
        "curl": ["http", "client", "headers"],
        "whatweb": ["web", "fingerprint", "technology"],
        "wget": ["http", "download", "client"],
    }
    return tag_map.get(name, [name])


def _make_nmap_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "-sT -T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_web_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()
        cmd = [tool_name] + extra_args
        if target:
            if tool_name in ("nikto",):
                cmd += ["-h", target]
            elif tool_name in ("nuclei",):
                cmd += ["-duc", "-u", target]
            elif tool_name in ("gobuster",):
                cmd += ["-u", target]
            elif tool_name in ("ffuf",):
                cmd += ["-u", target]
            elif tool_name in ("wpscan",):
                cmd += ["--url", target]
            elif tool_name in ("sqlmap",):
                cmd += ["-u", target]
            elif tool_name in ("whatweb",):
                cmd += [target]
            else:
                cmd += [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 300))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_portscan_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "-T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_recon_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        if tool_name == "amass":
            cmd = [tool_name, "enum", "-d", target] if target else [tool_name, "--help"]
        elif tool_name == "subfinder":
            cmd = [tool_name, "-d", target] if target else [tool_name, "--help"]
        elif tool_name == "shodan":
            cmd = (
                [tool_name, "info"]
                if not target or target.startswith("-")
                else [tool_name, "host", target]
            )
        else:
            cmd = [tool_name, "--help"]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_brute_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        cmd = [tool_name, "-l", target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_network_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        if tool_name in ("bettercap", "ettercap") and target:
            cmd = [tool_name, "-T", target, "-silent"] if tool_name == "bettercap" else [tool_name, "-T", target, "-M", "arp"]
        elif tool_name == "aircrack-ng" and "mode" in kwargs:
            mode = kwargs["mode"]
            if mode == "capture":
                cmd = [tool_name, "-c", target] if target else [tool_name, "--help"]
            elif mode == "crack":
                pcap = kwargs.get("pcap", "")
                wordlist = kwargs.get("wordlist", "")
                cmd = [tool_name, "-w", wordlist, pcap] if pcap and wordlist else [tool_name, "--help"]
            else:
                cmd = [tool_name, "--help"]
        else:
            cmd = [tool_name, "--help"]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 60))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }
    return handler


def _make_crypto_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        if tool_name == "hashcat" and target:
            hashfile = kwargs.get("hashfile", target)
            wordlist = kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            mode = kwargs.get("mode", "0")
            cmd = [tool_name, "-m", mode, "-a", "0", hashfile, wordlist]
        elif tool_name == "john" and target:
            cmd = [tool_name, target]
        else:
            cmd = [tool_name, "--help"]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }
    return handler


def _make_curl_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "-sI")
        cmd = [tool_name] + flags.split() + [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_dns_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        cmd = [tool_name, target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_whois_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        cmd = [tool_name, target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def _make_generic_handler(tool_name: str) -> ToolHandler:
    """Build a generic handler that passes kwargs as CLI arguments.

    Translates:
      handler(target="example.com", flags="-sV")  →  tool_name -sV example.com
    """

    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        cmd = [tool_name]
        target = kwargs.get("target", "")
        args_raw = kwargs.get("args", [])
        flags = kwargs.get("flags", "")
        if isinstance(args_raw, str):
            import shlex

            cmd.extend(shlex.split(args_raw))
        elif isinstance(args_raw, (list, tuple)):
            cmd.extend(str(a) for a in args_raw)
        if flags:
            cmd.extend(flags.split())
        if target:
            cmd.append(target)
        timeout = kwargs.get("timeout", 120)
        try:
            result = await safe_run_async(cmd, timeout=timeout)
            return {
                "status": "success" if result.exit_code == 0 else "error",
                "output": result.stdout,
                "error": result.stderr,
                "exit_code": result.exit_code,
                "tool": tool_name,
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc), "tool": tool_name}

    return handler
