# MCP Integration

Siyarix supports the Model Context Protocol (MCP) for connecting to external MCP servers that provide enhanced tool use and data gathering capabilities.

## Overview

The MCP client (`mcp_integration.py`) connects to MCP-compatible servers, discovers available tools, and invokes them on demand.

## Connecting to an MCP server

```bash
# Configure MCP endpoint
siyarix config set mcp_endpoint http://localhost:8080

# Verify connection
siyarix health
# Should show MCP: connected
```

## How it works

The `MCPClient`:

1. **Connect**: Sends HTTP GET to `{endpoint}/health`
2. **Discover tools**: Queries `{endpoint}/tools` for available tools
3. **Invoke tools**: Calls `{endpoint}/tools/{name}/call` with parameters
4. **Monitor**: Periodic health checks maintain connection state

### Tool discovery

```python
client = MCPClient(endpoint="http://localhost:8080")
await client.connect()

tools = client.list_tools()
for tool in tools:
    print(f"{tool.name}: {tool.description}")
```

### Tool invocation

```python
result = await client.call_tool("scan", {"target": "10.0.0.1"})
```

## Data model

```python
@dataclass
class MCPTool:
    name: str
    description: str
    parameters: dict  # JSON Schema for tool parameters
```

## Use cases

- **Research mode**: Connect to specialized security research MCP servers
- **Custom tools**: Expose proprietary tools via MCP without modifying Siyarix
- **Data enrichment**: Query external threat intelligence MCP servers
- **Orchestration**: Chain MCP tools with native Siyarix capabilities

## Requirements

- MCP server must be running and accessible at the configured endpoint
- `httpx` package must be installed (included as core dependency)
- Endpoint is configured via `mcp_endpoint` setting or environment variable
