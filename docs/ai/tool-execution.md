# 🚀 Tool Execution Architecture

Welcome to the **Tool Execution Pipeline** documentation! This guide explains how AI-planned tools are seamlessly discovered, registered, evaluated, and executed within Siyarix. 

Our pipeline is designed to be robust and secure, handling everything from cross-platform installation and availability checks to output parsing and error recovery. 

---

## 🔄 The Tool Lifecycle

Understanding the tool lifecycle is key to working with Siyarix. Every time a tool is invoked, it flows through this structured pipeline:

```text
Discovery 🔍 (ToolRegistry) 
  → Registration 📝 (ToolCapabilityGraph)
  → Availability Check ✅ (ToolAvailabilityContext)
  → Permission Gate 🛡️ (PermissionGate + ShellReview)
  → Invocation ⚡ (ToolHandlers / internal_tools)
  → Output Capture 📥 (safe_run_async / safe_run_async_stream)
  → Danger Analysis 🚨 (DangerAnalyzer)
  → DLP Redaction 🕵️ (DLPEngine)
  → Finding Storage 💾 (Knowledge Graph)
  → Version Detection 🏷️ (ToolVersion)
  → Installation 📦 (ToolInstaller)
```

> [!NOTE]  
> This pipeline ensures that no tool is executed blindly. Every step adds a layer of security, context, or functionality!

---

## 🗂️ Tool Registry

The `ToolRegistry` (found in `registry.py`) is the beating heart of our tool management system. Think of it as the central hub that keeps track of what tools can do, how to call them, and how to understand their output. 

It maintains:
- **`ToolCapabilityGraph`**: For capability-based lookups and chaining.
- **Handler Map**: For tool-specific invocations.
- **`ParserRegistry`**: For parsing complex tool outputs into structured data.

```python
from siyarix.registry import ToolRegistry

registry = ToolRegistry()

# Discover curated tools and interpreter environments
registry.discover_from_path()  

# Scan every executable available on the system's $PATH
registry.scan_path()           
```

### 📝 Registration

Tools are registered as `ToolCapability` objects. These objects hold all the metadata needed to safely and effectively use a tool.

```python
from siyarix.tool_models import ToolCapability, ToolCategory, RiskLevel

# Example: Registering Nmap
tool = ToolCapability(
    name="nmap",
    description="Network port scanner and service detector",
    category=ToolCategory.RECON,
    risk_level=RiskLevel.MEDIUM,
    tags=["port-scan", "network", "service-detection"],
    binary="nmap",
    installed=True,
    version="7.95",
)

# Register the tool along with its custom handler
registry.register(tool, handler_factory=make_nmap_handler)
```

> [!TIP]
> Always provide clear and descriptive tags when registering custom tools. Tags are heavily used by the AI to find the right tool for the job!

### 🛠️ Supported Tools (Curated)

Out of the box, Siyarix includes **26 curated security tools** mapped to dedicated handlers, ensuring they work perfectly from day one:

| Tool | Category | Handler |
|------|----------|---------|
| **nmap** | `RECON` | `make_nmap_handler` |
| **nikto** | `SCANNING` | `make_web_handler` |
| **nuclei** | `SCANNING` | `make_web_handler` |
| **gobuster** | `SCANNING` | `make_web_handler` |
| **ffuf** | `SCANNING` | `make_web_handler` |
| **hydra** | `EXPLOITATION` | `make_brute_handler` |
| **masscan** | `RECON` | `make_portscan_handler` |
| **amass** | `RECON` | `make_recon_handler` |
| **subfinder** | `RECON` | `make_recon_handler` |
| **wpscan** | `SCANNING` | `make_web_handler` |
| **sqlmap** | `SCANNING` | `make_web_handler` |
| **shodan** | `RECON` | `make_recon_handler` |
| **bettercap** | `NETWORK` | `make_network_handler` |
| **ettercap** | `NETWORK` | `make_network_handler` |
| **aircrack-ng** | `NETWORK` | `make_network_handler` |
| **hashcat** | `CRYPTO` | `make_crypto_handler` |
| **john** | `CRYPTO` | `make_crypto_handler` |
| **burpsuite** | `WEB` | `make_web_handler` |
| **zaproxy** | `WEB` | `make_web_handler` |
| **whatweb** | `WEB` | `make_web_handler` |
| **curl** | `UTILITY` | `make_curl_handler` |
| **wget** | `UTILITY` | `make_curl_handler` |
| **dig** | `RECON` | `make_dns_handler` |
| **whois** | `RECON` | `make_whois_handler` |
| **graph_analyzer**| `REPORTING` | `make_graph_analyzer_handler` |
| **threat_intel** | `REPORTING` | `make_threat_intel_handler` |

*Plus 20+ built-in system/interpreter tools (like `ls`, `python3`, `node`, `go`) and any executables discovered on your `$PATH`.*

---

## 📊 Tool Data Model

### 🧩 ToolCapability

The `ToolCapability` dataclass represents everything we know about a tool:

```python
@dataclass
class ToolCapability:
    name: str                           # The tool's command name
    description: str                    # What the tool does
    category: ToolCategory              # Functional category (e.g., RECON)
    risk_level: RiskLevel               # Safety rating (SAFE to CRITICAL)
    aliases: list[str]                  # Other names for this tool
    tags: list[str]                     # Keywords for AI matching
    inputs: dict[str, str]              # What inputs the tool expects
    input_schema: dict[str, Any]        # JSON schema for input validation
    outputs: dict[str, str]             # What the tool returns
    dependencies: list[str]             # Other tools required to run
    related_tools: list[str]            # Similar alternatives
    workflows: list[str]                # Known workflow associations
    binary: str                         # Absolute or relative path to the binary
    version: str                        # Current installed version
    installed: bool                     # Is it available on the system?
    source: str                         # Where this metadata came from
    metadata: dict[str, Any]            # Extra info (e.g., ideal personas)
    parser: str                         # Name of the parser module to use
    availability: dict | None           # Logic rules for when this tool can run
    usage_count: int                    # Telemetry: times used
    last_used: float                    # Telemetry: timestamp of last use
    avg_duration_ms: float              # Telemetry: average runtime
```

### 🗂️ ToolCategory

Tools are grouped into logical categories to help the AI select the right approach:

| Category | Typical Tools |
|----------|--------------|
| `RECON` | nmap, masscan, amass, shodan |
| `SCANNING` | nikto, nuclei, sqlmap, gobuster |
| `EXPLOITATION`| hydra, metasploit |
| `POST_EXPLOIT`| mimikatz, bloodhound |
| `REPORTING` | graph_analyzer, threat_intel |
| `NETWORK` | bettercap, aircrack-ng |
| `WEB` | burpsuite, zaproxy, whatweb |
| `CRYPTO` | hashcat, john |
| `FORENSICS` | volatility, yara |
| `CONTAINER` | trivy, kube-bench |
| `CLOUD` | prowler, scoutsuite |
| `DEVSECOPS` | semgrep, gitleaks |
| `UTILITY` | curl, jq, python3 |

---

## 🕸️ Tool Capability Graph

The `ToolCapabilityGraph` (`tool_graph.py`) isn't just a list—it's an intelligent graph that understands how tools relate to one another. 

### 🔗 Pathfinding for Tool Chaining
Want to automatically pass the output of one tool to another? The graph finds the path:

```python
from siyarix.tool_graph import ToolCapabilityGraph

graph = ToolCapabilityGraph()
graph.add_tool(nmap_capability)
graph.add_tool(searchsploit_capability)
graph.add_edge(ToolEdge(source="nmap", target="searchsploit", weight=0.8))

# Automatically figure out how to chain nmap into searchsploit
chain = graph.get_chain("nmap", "searchsploit")  # Returns: ["nmap", "searchsploit"]
```

### 🎯 Optimal Tool Selection
When the AI knows the goal but not the specific tool, it asks the graph to score the best available options:

```python
# Score and rank available tools based on a natural language goal
results = graph.find_optimal_tools("fast port scan", available=["nmap", "masscan", "curl"])
```

> [!IMPORTANT]
> The capability graph is what gives the AI its "intuition" to choose `masscan` over `nmap` when speed is the primary objective!

---

## 🎮 Tool Handlers

A tool handler (`tool_handlers.py`) acts as the translator between our Python pipeline and the raw CLI tool. It safely constructs commands, validates arguments, and manages timeouts.

### 📝 Example: A Custom Handler

Here is how a typical handler wraps a tool:

```python
def make_nmap_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        
        # Guard against empty targets
        if not target:
            return {"status": "error", "error": "No target specified", "tool": tool_name}
            
        flags = kwargs.get("flags", "-sT -T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        
        # Execute safely
        result = await _run(tool_name, cmd, kwargs.get("timeout", 120))
        
        return {
            "status": "success" if not result.exit_code else "error", 
            "output": result.stdout
        }
    return handler
```

### 🧠 Internal Tools
Not all tools are external binaries. Some (`internal_tools.py`) interact directly with Siyarix's own memory and databases:
- `graph_analyzer`: Queries the Knowledge Graph (e.g., shortest paths, blast radius).
- `threat_intel`: Performs lookups against built-in CVE and MITRE databases.

---

## 🚦 Availability Evaluation

Before a tool is even suggested to the AI, `ToolAvailabilityContext` checks if it can actually run in the current environment. 

### 📡 Availability Signals
Signals are JSON expressions that define requirements:

| Requirement | Example Expression |
|-------------|--------------------|
| API Key | `{"auth": {"provider": "openai"}}` |
| Config Flag | `{"config": {"key": "stealth", "value": "enabled"}}` |
| Environment | `{"env": {"var": "API_KEY"}}` |
| Binary Path | `{"installed": {"name": "nmap"}}` |

### 🔀 Boolean Logic
You can combine signals for complex requirements:

```python
# The tool requires BOTH nmap installed AND stealth mode enabled
result = evaluate_availability({
    "allOf": [
        {"installed": {"name": "nmap"}},
        {"env": {"var": "STEALTH_MODE"}}
    ]
}, ctx)
```

---

## 🏷️ Tool Metadata & Fallbacks

Tool metadata (`tool_metadata.py`) is gathered using a reliable two-tier system:
1. **`data/cyber_tools.json`**: Our primary, extensible database of tool definitions.
2. **Built-in static mappings**: Safe defaults for tools not yet present in the JSON file.

```python
from siyarix.tool_metadata import categorize_tool, risk_for_tool, describe_tool

category = categorize_tool("nmap")     # Returns: ToolCategory.RECON
risk = risk_for_tool("metasploit")     # Returns: RiskLevel.HIGH
desc = describe_tool("nuclei")         # Returns: "Template-based vulnerability scanner"
```

---

## ⚡ Execution Engine

At the core of execution is `subprocess_utils.py`, built for ultimate safety and performance. 

It provides multiple execution modes:
- `safe_run_async`: Standard non-blocking execution.
- `safe_run_async_stream`: Real-time, line-by-line streaming.
- `safe_run_sync`: Standard blocking execution.
- `safe_run_sandboxed`: Isolated execution via `bwrap` or Docker.

### 🛡️ Security Features
Execution isn't just about running commands; it's about running them *safely*.
- **Destructive Pattern Detection**: Automatically blocks commands like `rm -rf /` or fork bombs.
- **Path Traversal Protection**: Stops `../` payload injections.
- **Orphan Tracking**: Ensures lingering processes are cleaned up.
- **Sudo Support**: Handles password prompts seamlessly.
- **Sandboxing**: Runs high-risk tools in restricted environments.

---

## 🧩 Output Parsing

Running a tool is only half the battle. `ParserRegistry` automatically converts messy CLI output into structured `Finding` objects. 

### 🔄 The Finding Lifecycle
1. **Parse**: The dedicated parser reads the raw stdout.
2. **Ingest**: Sent to the Knowledge Graph via `_ingest_finding_to_graph()`.
3. **Store**: Saved to the offline local database.
4. **Log**: Recorded in the audit trail.
5. **Deduplicate**: Filtered by MD5 hash (target + port + CVE + severity) to prevent noise.
6. **Display**: Presented cleanly to the user.

---

## 📦 Automated Installation

Missing a tool? The `ToolInstaller` (`tool_installer.py`) has your back. It abstracts package management across OS platforms.

```python
from siyarix.tool_installer import ToolInstaller

installer = ToolInstaller()

# Automatically detects OS and runs the right package manager
result = installer.install("nmap") 
```

> [!TIP]
> **Windows Users**: The installer uses Winget (falling back to Choco). It includes predefined mappings so asking for `nmap` automatically translates to `winget install Insecure.Nmap`.

---

## 🩹 Error Handling & Recovery

Siyarix is designed to gracefully recover from tool failures.

### 🚫 Tool Not Found
If a tool is missing, the system doesn't just crash. It provides actionable installation hints:
```text
Binary not found: 'nmap' is not installed or not found in PATH.
Install it with: winget install Insecure.Nmap
```

### 🔁 Auto-Recovery
If a tool fails during execution (e.g., "Connection Refused" during a ping sweep), the AI can automatically propose a recovery plan, such as modifying the flags (e.g., adding `-Pn`).

---

## 🛠️ Adding Custom Tools

Extending Siyarix is incredibly simple. Just add your tool to `custom_tools.json` in your configuration directory:

```json
{
    "my-custom-scanner": {
        "description": "Proprietary internal security scanner",
        "category": "scanning",
        "risk_level": "medium",
        "aliases": ["mcs"],
        "tags": ["custom", "internal-only"],
        "binary": "my-custom-scanner",
        "version": "1.2"
    }
}
```

---

## 📚 Module Reference

Need to dive deeper? Here is where everything lives:

| Module | Location | What it does |
|--------|----------|--------------|
| **ToolRegistry** | `src/siyarix/registry.py` | Central hub for discovery, handlers, and parsers. |
| **ToolCapability** | `src/siyarix/tool_models.py` | Data models and enums. |
| **ToolGraph** | `src/siyarix/tool_graph.py` | Graph logic for chaining and scoring. |
| **ToolHandlers** | `src/siyarix/tool_handlers.py` | Wrapper logic for external binaries. |
| **InternalTools** | `src/siyarix/internal_tools.py` | Handlers for internal Siyarix systems. |
| **Availability** | `src/siyarix/tool_availability.py` | Context and signal evaluation. |
| **Installer** | `src/siyarix/tool_installer.py` | OS-agnostic auto-installer. |
| **Metadata** | `src/siyarix/tool_metadata.py` | Categorization and tagging engine. |
| **Execution** | `src/siyarix/subprocess_utils.py` | Secure, async process execution. |
| **Security** | `src/siyarix/security_hardening.py` | Threat analysis and DLP redaction. |
| **Parsers** | `src/siyarix/parsers/` | 100+ modules turning text into JSON. |
