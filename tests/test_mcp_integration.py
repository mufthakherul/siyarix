# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.mcp_integration — MCP client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch


from siyarix.mcp_integration import MCPClient, MCPTool


class TestMCPTool:
    def test_attributes(self) -> None:
        tool = MCPTool(name="scan", description="Run a scan", parameters={"target": "string"})
        assert tool.name == "scan"
        assert tool.description == "Run a scan"
        assert tool.parameters == {"target": "string"}

    def test_defaults(self) -> None:
        tool = MCPTool(name="empty")
        assert tool.description == ""
        assert tool.parameters == {}


class TestMCPClient:
    def test_initial_state(self) -> None:
        client = MCPClient()
        assert client.is_connected is False

    def test_initial_state_with_endpoint(self) -> None:
        client = MCPClient(endpoint="http://localhost:8080")
        assert client.is_connected is False

    @patch("httpx.AsyncClient")
    async def test_connect_success(self, mock_async_client: MagicMock) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client

        health_resp = MagicMock()
        health_resp.status_code = 200

        tools_resp = MagicMock()
        tools_resp.status_code = 200
        tools_resp.json.return_value = {
            "tools": [
                {"name": "scanner", "description": "Scan tool", "parameters": {}}
            ]
        }

        mock_client.get.side_effect = [health_resp, tools_resp]
        mock_async_client.return_value = mock_client

        client = MCPClient()
        result = await client.connect("http://mcp.local:9000")
        assert result is True
        assert client.is_connected is True
        assert len(client._tools) == 1
        assert client._tools[0].name == "scanner"

    async def test_connect_no_endpoint(self) -> None:
        client = MCPClient()
        result = await client.connect(endpoint="")
        assert result is False

    @patch("httpx.AsyncClient")
    async def test_connect_health_fails(self, mock_async_client: MagicMock) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        health_resp = MagicMock()
        health_resp.status_code = 500
        mock_client.get.return_value = health_resp
        mock_async_client.return_value = mock_client

        client = MCPClient()
        result = await client.connect("http://bad:8080")
        assert result is False

    async def test_connect_import_error(self) -> None:
        with patch("builtins.__import__", side_effect=ImportError("no httpx")):
            client = MCPClient()
            result = await client.connect("http://localhost:8080")
            assert result is False

    @patch("httpx.AsyncClient")
    async def test_connect_exception(self, mock_async_client: MagicMock) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.side_effect = RuntimeError("connection refused")
        mock_async_client.return_value = mock_client

        client = MCPClient()
        result = await client.connect("http://localhost:8080")
        assert result is False

    @patch("httpx.AsyncClient")
    async def test_call_tool_success(self, mock_async_client: MagicMock) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.json.return_value = {"result": "ok"}
        mock_client.post.return_value = post_resp
        mock_async_client.return_value = mock_client

        client = MCPClient()
        client._connected = True
        client._endpoint = "http://localhost:8080"

        result = await client.call_tool("scan", {"target": "example.com"})
        assert result == {"result": "ok"}

    @patch("httpx.AsyncClient")
    async def test_call_tool_http_error(self, mock_async_client: MagicMock) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        post_resp = MagicMock()
        post_resp.status_code = 500
        post_resp.text = "Internal error"
        mock_client.post.return_value = post_resp
        mock_async_client.return_value = mock_client

        client = MCPClient()
        client._connected = True
        client._endpoint = "http://localhost:8080"

        result = await client.call_tool("scan", {"target": "x"})
        assert result["error"] == "HTTP 500"

    async def test_call_tool_not_connected(self) -> None:
        client = MCPClient()
        result = await client.call_tool("scan")
        assert result == {"error": "not connected"}

    @patch("httpx.AsyncClient")
    async def test_call_tool_exception(self, mock_async_client: MagicMock) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.post.side_effect = RuntimeError("timeout")
        mock_async_client.return_value = mock_client

        client = MCPClient()
        client._connected = True
        client._endpoint = "http://localhost:8080"

        result = await client.call_tool("scan")
        assert "error" in result

    async def test_disconnect(self) -> None:
        client = MCPClient()
        client._connected = True
        client._tools = [MCPTool(name="t")]
        await client.disconnect()
        assert client.is_connected is False
        assert client._tools == []
