# SPDX-License-Identifier: AGPL-3.0-or-later
"""Model Context Protocol integration for external tool servers."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from .registry import ToolCapability, ToolCategory, RiskLevel, ToolRegistry
from .events import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)


@dataclass
class MCPServerConfig:
    name: str
    url: str
    transport: str = "http"
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    enabled: bool = True


@dataclass
class MCPTool:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    server: str = ""


class MCPClient:
    def __init__(self) -> None:
        self._servers: dict[str, MCPServerConfig] = {}
        self._tools: dict[str, MCPTool] = {}
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._event_bus = get_event_bus()

    async def connect(self, config: MCPServerConfig) -> bool:
        try:
            client = httpx.AsyncClient(
                base_url=config.url, headers=config.headers, timeout=config.timeout
            )
            response = await client.get("/tools")
            if response.status_code == 200:
                tools = response.json().get("tools", [])
                self._servers[config.name] = config
                self._clients[config.name] = client
                for t in tools:
                    tool = MCPTool(
                        name=f"{config.name}:{t['name']}",
                        description=t.get("description", ""),
                        input_schema=t.get("inputSchema", {}),
                        server=config.name,
                    )
                    self._tools[tool.name] = tool
                await self._event_bus.emit(
                    Event(
                        type=EventType.MCP_CONNECTED,
                        source="mcp",
                        data={"server": config.name, "tools": len(tools)},
                    )
                )
                return True
        except Exception as e:
            logger.exception("Failed to connect to MCP server: %s", config.name)
            await self._event_bus.emit(
                Event(
                    type=EventType.MCP_DISCONNECTED,
                    source="mcp",
                    data={"server": config.name, "error": str(e)},
                )
            )
        return False

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if not tool:
            return {"status": "error", "error": f"MCP tool not found: {tool_name}"}
        client = self._clients.get(tool.server)
        if not client:
            return {"status": "error", "error": f"MCP server not connected: {tool.server}"}
        try:
            response = await client.post(
                "/call", json={"tool": tool_name.split(":", 1)[1], "params": arguments}
            )
            if response.status_code == 200:
                result = response.json()
                result.setdefault("status", "success")
                result.setdefault("tool", tool_name)
                return result
            return {"status": "error", "error": f"MCP call failed: {response.status_code}"}
        except Exception as e:
            return {"status": "error", "error": f"MCP call error: {e}"}

    async def disconnect(self, server_name: str) -> None:
        client = self._clients.pop(server_name, None)
        if client:
            await client.aclose()
        self._servers.pop(server_name, None)
        self._tools = {k: v for k, v in self._tools.items() if v.server != server_name}

    def list_tools(self) -> list[MCPTool]:
        return list(self._tools.values())

    def list_servers(self) -> list[MCPServerConfig]:
        return list(self._servers.values())

    async def shutdown(self) -> None:
        for name in list(self._servers.keys()):
            await self.disconnect(name)


class MCPManager:
    def __init__(self) -> None:
        self._client = MCPClient()

    @property
    def client(self) -> MCPClient:
        return self._client

    async def register_server(self, config: MCPServerConfig) -> bool:
        return await self._client.connect(config)

    async def register_with_registry(self, registry: ToolRegistry) -> int:
        count = 0
        for tool in self._client.list_tools():

            def _make_handler(t: MCPTool) -> Any:
                return lambda **kw: self._client.call_tool(t.name, kw)

            registry.register(
                ToolCapability(
                    name=tool.name,
                    description=tool.description,
                    category=ToolCategory.UTILITY,
                    risk_level=RiskLevel.MEDIUM,
                    tags=["mcp", tool.server],
                ),
                handler=_make_handler(tool),
            )
            count += 1
        return count

    def load_config(self, config: dict[str, Any]) -> int:
        count = 0
        for name, sc in config.items():
            if isinstance(sc, dict) and sc.get("enabled", True):
                mc = MCPServerConfig(
                    name=name,
                    url=sc.get("url", ""),
                    transport=sc.get("transport", "http"),
                    headers=sc.get("headers", {}),
                    timeout=sc.get("timeout", 30.0),
                )
                asyncio.create_task(self.register_server(mc))
                count += 1
        return count

    async def shutdown(self) -> None:
        await self._client.shutdown()

    def stats(self) -> dict[str, Any]:
        return {
            "servers": len(self._client.list_servers()),
            "tools": len(self._client.list_tools()),
        }

__all__ = [
    "MCPServerConfig",
    "MCPTool",
    "MCPClient",
    "MCPManager",
]
