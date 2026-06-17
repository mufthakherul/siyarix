# Tool Execution

AI-planned tools are executed through a structured pipeline that handles discovery, availability evaluation, invocation, output parsing, error recovery, and auto-installation.

---

## Tool Lifecycle

```
Discovery (ToolRegistry) → Selection (capability match)
  → Availability Check (ToolAvailabilityContext)
  → Invocation (ToolHandlers / raw shell)
  → Output Capture (safe_run_async_stream)
  → Danger Analysis (DangerAnalyzer)
  → Secret Redaction (SecretRedactor)
  → Finding Storage (Knowledge Graph)
```

---

## Tool Discovery

`ToolRegistry` scans PATH at startup for known security tools, checks versions, and builds a capability index.

### Discovery Process

```python
registry = ToolRegistry()
registry.scan_path()  # Scans PATH, checks versions
```

For each discovered binary:

1. Check if binary exists on PATH via `shutil.which()`
2. Run `--version` to verify and extract version string
3. Record tool info: name, binary path, version, tags
4. Store in `ToolCapabilityGraph` for capability-based lookups

### Tool Metadata

Tools have metadata stored in two layers:

1. **`data/cyber_tools.json`** — extensible JSON database of tool definitions
2. **Static mappings** in `tool_metadata.py` — fallback for tools not yet in the database

```python
from siyarix.tool_metadata import categorize_tool, get_tool_metadata

cat = categorize_tool("nmap")          # ToolCategory.RECON
meta = get_tool_metadata("nuclei")     # ToolCapability with tags, inputs, outputs
```

### Tool Categories

| Category | Example Tools |
|----------|--------------|
| `RECON` | nmap, masscan, amass, subfinder, shodan |
| `SCANNING` | nikto, nuclei, wpscan, zaproxy |
| `EXPLOITATION` | metasploit, sqlmap, hydra, searchsploit |
| `POST_EXPLOIT` | mimikatz, bloodhound, impacket |
| `NETWORK` | bettercap, ettercap, tcpdump, wireshark |
| `WEB` | ffuf, gobuster, katana, httpx |
| `CRYPTO` | hashcat, john, openssl |
| `FORENSICS` | volatility, yara, exiftool |
| `CONTAINER` | trivy, grype, kube-bench |
| `CLOUD` | prowler, scoutsuite, pacu |
| `DEVSECOPS` | semgrep, gitleaks, trufflehog |
| `UTILITY` | curl, dig, nslookup, whois, jq |

---

## Tool Data Model

```python
@dataclass
class ToolCapability:
    name: str                           # Tool name (e.g., "nmap")
    description: str                    # Human-readable description
    category: ToolCategory              # RECON, SCANNING, EXPLOITATION, etc.
    risk_level: RiskLevel               # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    aliases: list[str]                  # Alternative names
    tags: list[str]                     # Capability tags
    inputs: dict[str, str]              # Expected input parameters
    input_schema: dict[str, Any]        # JSON schema for inputs
    outputs: dict[str, str]             # Output structure
    dependencies: list[str]             # Required tools
    related_tools: list[str]            # Similar tools
    workflows: list[str]                # Associated workflows
    binary: str                         # Path to binary
    version: str                        # Detected version
    installed: bool                     # Available on PATH
    parser: str                         # Parser module name
    availability: dict | None           # Availability expression
    usage_count: int                    # Number of times used
    avg_duration_ms: float              # Average execution time
```

---

## Tool Availability Evaluation

`ToolAvailabilityContext` evaluates whether a tool can run in the current environment:

```python
from siyarix.tool_availability import (
    ToolAvailabilityContext,
    evaluate_availability,
    check_tool_available,
)

ctx = ToolAvailabilityContext()
result = evaluate_availability({"installed": {"name": "nmap"}}, ctx)
# ToolAvailabilityResult(available=True, diagnostics=[...])
```

### Availability Signals

| Signal | Evaluates | Expression |
|--------|-----------|------------|
| `always` | Always available | `{"always": true}` |
| `auth` | Provider API key configured | `{"auth": {"provider": "openai"}}` |
| `config` | Config value set/matches | `{"config": {"key": "feature_x", "value": "enabled"}}` |
| `env` | Environment variable set/matches | `{"env": {"var": "API_KEY"}}` |
| `installed` | Binary exists on PATH | `{"installed": {"name": "nmap"}}` |

### Boolean Expressions

```python
# All must pass
result = evaluate_availability({
    "allOf": [
        {"installed": {"name": "nmap"}},
        {"env": {"var": "STEALTH_MODE"}}
    ]
}, ctx)

# Any must pass
result = evaluate_availability({
    "anyOf": [
        {"installed": {"name": "nmap"}},
        {"installed": {"name": "masscan"}}
    ]
}, ctx)
```

---

## Tool Selection

The planner selects tools by capability tags:

```python
def select_tools(intent: str, target: str) -> list[str]:
    tags = INTENT_TO_TAGS[intent]          # e.g., "port_scan" → ["port_scanning"]
    tools = registry.find_by_tags(tags)    # e.g., [nmap, masscan, rustscan]
    return filter_by_platform(tools)       # Filter for current OS
```

### Capability Graph

`ToolCapabilityGraph` maintains a graph of tool relationships and supports pathfinding for tool chaining:

```python
graph = ToolCapabilityGraph()
graph.add_tool(nmap_capability)
graph.add_edge(ToolEdge(source="nmap", target="searchsploit", weight=0.8))

# Find chain from nmap → searchsploit
chain = graph.get_chain("nmap", "searchsploit")  # ["nmap", "searchsploit"]
```

---

## Tool Handlers

Tool-specific invocation handlers in `tool_handlers.py` manage arguments and execution:

| Handler | Tools | Features |
|---------|-------|----------|
| `make_nmap_handler` | nmap | Flags, target, timeout |
| `make_portscan_handler` | masscan, rustscan | Flags, target, timeout |
| `make_web_handler` | nikto, nuclei, gobuster, ffuf, wpscan, sqlmap | Target flags, stealth decoys, extra args |
| `make_recon_handler` | amass, subfinder, shodan | Tool-specific subcommands |
| `make_brute_handler` | hydra | Service, username, wordlist |
| `make_network_handler` | bettercap, ettercap, aircrack-ng | Mode-specific arguments |
| `make_crypto_handler` | hashcat, john | Hash file, wordlist, mode |
| `make_curl_handler` | curl | Flags, target |
| `make_dns_handler` | dig, nslookup | Flags, target |
| `make_whois_handler` | whois | Target |
| `make_generic_handler` | Any tool | Target validation, args, flags |

### Example Handler

```python
# Port scan handler
async def handler(**kwargs):
    target = kwargs.get("target", "")
    flags = kwargs.get("flags", "-T4 --top-ports 100")
    cmd = [tool_name] + flags.split() + [target]
    result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
    return {"status": "success", "output": result.stdout, ...}
```

---

## Command Construction

Commands are built from tool metadata with injection guards:

```python
tool = registry.get("nmap")
command = f"{tool.binary} {tool.default_args} {target}"

# With injection validation
from siyarix.tool_handlers import _run
result = await _run(tool_name, cmd, timeout=120)
```

All commands pass through `InputValidator.check_args_injection()` and `InputValidator.sanitize_args()` before execution.

---

## Execution

```python
from siyarix.subprocess_utils import safe_run_async, safe_run_async_stream

# Non-streaming
result = await safe_run_async(
    command=["nmap", "-sV", target],
    timeout=config.get("scan_timeout", 300),
)

# Streaming (line-by-line output)
result = await safe_run_async_stream(
    command,
    timeout=agent_timeout,
    on_stdout=lambda line: handle_line(line),
    on_stderr=lambda line: handle_line(line),
)
```

### Execution Features

| Feature | Description |
|---------|-------------|
| **Timeout** | Process killed after `timeout` seconds |
| **Environment injection** | API keys, proxy settings injected as env vars |
| **PTY support** | Interactive tools via PTY allocation |
| **Output capture** | stdout + stderr with configurable size limits |
| **Streaming** | Line-by-line output for real-time display |
| **Injection guards** | Pre-execution arg validation and sanitization |

---

## Output Parsing

Parsers convert raw tool output into structured `Finding` objects. Located in `src/siyarix/parsers/`.

### Supported Parsers (partial list)

| Parser | Tool | Input Format |
|--------|------|-------------|
| `nmap_parser.py` | Nmap | XML (`-oX`) |
| `masscan_parser.py` | Masscan | JSON |
| `nuclei_parser.py` | Nuclei | JSON |
| `metasploit_parser.py` | Metasploit | JSON |
| `hydra_parser.py` | Hydra | Text |
| `ffuf_parser.py` | FFUF | JSON |
| `gobuster_parser.py` | Gobuster | Text |
| `nikto_parser.py` | Nikto | Text/JSON |
| `burpsuite_parser.py` | Burp Suite | XML |
| `sqlmap_parser.py` | SQLMap | Text |
| `zaproxy_parser.py` | ZAP | JSON/XML |
| `wpscan_parser.py` | WPScan | JSON |
| `shodan_parser.py` | Shodan | JSON |
| `subfinder_parser.py` | Subfinder | Text/JSON |
| `amass_parser.py` | Amass | Text/JSON |
| `impacket_parser.py` | Impacket | Text |
| `bettercap_parser.py` | Bettercap | JSON |
| `trivy_parser.py` | Trivy | JSON |
| `grype_parser.py` | Grype | JSON |
| `semgrep_parser.py` | Semgrep | JSON |
| `gitleaks_parser.py` | Gitleaks | JSON |
| `trufflehog_parser.py` | TruffleHog | JSON |
| ... and 90+ more | Various | Various |

### Finding Data Model

```python
@dataclass
class Finding:
    tool: str                           # Source tool
    target: str                         # Scanned target
    port: int | None                    # Port number (if applicable)
    service: str | None                 # Service name
    vulnerability: str | None           # CVE or vulnerability ID
    severity: str                       # critical, high, medium, low, info
    evidence: str                       # Supporting evidence
    timestamp: str                      # ISO 8601 timestamp
```

### Finding Lifecycle

1. **Parsed** from raw tool output by dedicated parser
2. **Added** to the knowledge graph
3. **Stored** in the offline store
4. **Logged** to the audit trail
5. **Displayed** to the user

---

## Error Handling

### Tool Not Found

`DynamicResolver` tries these locations:
- PATH
- Common install directories (`/usr/bin`, `/usr/local/bin`)
- WSL paths (for Windows WSL2)
- Falls back to `ToolInstaller` for auto-install

### Tool Execution Failure

```python
if is_transient_error(exit_code, stderr):
    await asyncio.sleep(backoff_delay)
    result = await retry_execution()
else:
    log_error("Non-transient tool failure")
    mark_plan_step_failed()
```

### Parser Failure

If a parser fails to match expected output format:
1. Raw output is logged for debugging
2. Finding extraction is skipped for that tool
3. The engine continues with remaining steps

---

## Tool Auto-Install

`ToolInstaller` handles automated installation across platforms:

```python
from siyarix.tool_installer import ToolInstaller

installer = ToolInstaller()
result = installer.install("nmap")
# Result: ToolInstallResult(tool="nmap", success=True, method="auto")
```

### Platform Support

| Platform | Package Managers Used |
|----------|---------------------|
| Windows | `winget` → `choco` |
| Linux | `apt-get` → `pacman` → `dnf` → `apk` |
| macOS | `brew` |

```python
def install_tool(self, tool: str, pkg: str | None = None) -> bool:
    if os.name == "nt":
        return self._install_win(tool, pkg)
    return self._install_nix(tool, pkg)
```

Windows uses a predefined Winget ID mapping for common tools (nmap, ffuf, nuclei, yara, etc.) and falls back to choco.

---

## Tool Call Repair

When an LLM outputs tool calls as plain text instead of structured JSON, `ToolCallRepair` parses and promotes them:

```python
from siyarix.tool_call_repair import (
    promote_to_native_tool_calls,
    parse_plain_text_tool_calls,
    has_plain_text_tool_calls,
)

# Check if repair is needed
if has_plain_text_tool_calls(response):
    cleaned, native_calls = promote_to_native_tool_calls(
        response,
        allowed_tools=["nmap", "masscan"],
        fuzzy=True,  # Enable fuzzy name matching
    )
```

### Supported Syntaxes

| Syntax | Example |
|--------|---------|
| Bracket | `[nmap]{"target": "10.0.0.1"}` |
| XML | `<function=nmap><parameter=target>10.0.0.1</parameter></function>` |

### Fuzzy Name Matching

When `fuzzy=True`, tool names are matched with Levenshtein distance ≤ 2, supporting:
- Exact match
- Case-insensitive match
- Substring match
- Typo tolerance (edit distance ≤ 2)

---

## Related Modules

| Module | Path | Purpose |
|--------|------|---------|
| `ToolCapability` | `src/siyarix/tool_models.py` | Tool data model (name, category, risk, tags, etc.) |
| `ToolCapabilityGraph` | `src/siyarix/tool_graph.py` | Tool chaining and similarity graph |
| `ToolAvailabilityContext` | `src/siyarix/tool_availability.py` | Pre-execution availability evaluation |
| `ToolHandlers` | `src/siyarix/tool_handlers.py` | Tool-specific invocation handlers |
| `ToolInstaller` | `src/siyarix/tool_installer.py` | Cross-platform auto-installation |
| `ToolCallRepair` | `src/siyarix/tool_call_repair.py` | Plain-text tool call parsing and promotion |
| `tool_metadata.py` | `src/siyarix/tool_metadata.py` | Tool categorization and metadata lookup |
| `security_hardening.py` | `src/siyarix/security_hardening.py` | Danger analysis, input validation, secret redaction |
| `subprocess_utils.py` | `src/siyarix/subprocess_utils.py` | Async subprocess execution (safe_run_async) |
| `parsers/` | `src/siyarix/parsers/` | Tool-specific output parsers (100+) |
