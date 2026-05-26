"""
MCP (Model Context Protocol) integration for research mode.

Supports connecting to MCP servers for enhanced tool use
and data gathering, as described in Chapter 9.3.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class MCPTool:
    name: str
    description: str = ""
    parameters: dict = field(default_factory=dict)


class MCPClient:
    """Lightweight MCP client for connecting to MCP servers."""

    def __init__(self, endpoint: str = ""):
        self._endpoint = endpoint
        self._connected = False
        self._tools: list[MCPTool] = []

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self, endpoint: str = "") -> bool:
        self._endpoint = endpoint or self._endpoint
        if not self._endpoint:
            logger.warning("No MCP endpoint configured")
            return False
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self._endpoint}/health")
                if resp.status_code == 200:
                    self._connected = True
                    # Fetch available tools
                    tools_resp = await client.get(f"{self._endpoint}/tools")
                    if tools_resp.status_code == 200:
                        tools_data = tools_resp.json()
                        self._tools = [
                            MCPTool(**t) for t in tools_data.get("tools", [])
                        ]
                    logger.info("Connected to MCP server at %s", self._endpoint)
                    return True
        except ImportError:
            logger.debug("httpx not available; MCP connection requires httpx")
        except Exception as exc:
            logger.warning("MCP connection failed: %s", exc)
        return False

    async def call_tool(
        self, name: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if not self._connected:
            logger.warning("MCP client not connected")
            return {"error": "not connected"}
        try:
            import httpx

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{self._endpoint}/tools/{name}/call",
                    json=params or {},
                )
                if resp.status_code == 200:
                    return resp.json()
                return {"error": f"HTTP {resp.status_code}", "detail": resp.text}
        except Exception as exc:
            logger.exception("MCP tool call failed: %s", exc)
            return {"error": str(exc)}

    async def disconnect(self) -> None:
        self._connected = False
        self._tools = []


__all__ = ["MCPClient", "MCPTool"]
