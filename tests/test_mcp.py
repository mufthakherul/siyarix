# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest
from siyarix.mcp import MCPServerConfig, MCPTool, MCPClient, MCPManager

@pytest.mark.asyncio
async def test_mcp_server_config():
    config = MCPServerConfig(name="test", url="http://localhost:8080")
    assert config.name == "test"
    assert config.url == "http://localhost:8080"
    assert config.transport == "http"
    assert config.enabled is True

@pytest.mark.asyncio
async def test_mcp_client_init():
    client = MCPClient()
    assert len(client.list_servers()) == 0
    assert len(client.list_tools()) == 0

@pytest.mark.asyncio
async def test_mcp_manager_init():
    manager = MCPManager()
    assert manager.client is not None
    assert manager.stats() == {"servers": 0, "tools": 0}

@pytest.mark.asyncio
async def test_mcp_client_disconnect_unknown():
    client = MCPClient()
    await client.disconnect("unknown")
    assert len(client.list_servers()) == 0

@pytest.mark.asyncio
async def test_mcp_client_shutdown():
    client = MCPClient()
    await client.shutdown()

@pytest.mark.asyncio
async def test_mcp_manager_shutdown():
    manager = MCPManager()
    await manager.shutdown()

@pytest.mark.asyncio
async def test_mcp_call_tool_not_found():
    client = MCPClient()
    res = await client.call_tool("unknown:tool", {})
    assert res == {"status": "error", "error": "MCP tool not found: unknown:tool"}

@pytest.mark.asyncio
async def test_mcp_manager_load_config():
    manager = MCPManager()
    count = manager.load_config({
        "server1": {"url": "http://test", "enabled": True},
        "server2": {"url": "http://test2", "enabled": False}
    })
    assert count == 1
