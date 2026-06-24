# Agent Reasoning Pipeline

The agent reasoning pipeline transforms user objectives into executed actions through structured **observe–reason–act–reflect** loops. Siyarix v1.0.0 supports three execution modes — **integrated**, **autonomous**, and **registry/offline** — each with a distinct reasoning strategy.

---

## Execution Modes

| Mode | Description | LLM Required |
|------|-------------|-------------|
| `integrated` | Agent loop with LLM; falls back to registry engine on failure | No |
| `autonomous` | Agent loop with LLM; stops if no provider available | Yes |
| `registry` | Deterministic rule-based planner only | No |
| `offline` | Deterministic rule-based planner only | No |

---

## Observe–Reason–Act–Reflect Loop

The `LLMEngineMixin._execute_agent()` method implements a multi-turn reasoning loop:

```
while objective_incomplete and iterations < max_waves:
    # Observe
    state = collect_environment_state()
    findings = knowledge_graph.query(objective.targets)

    # Reason
    analysis = analyze_findings(findings, state)
    next_action = select_next_action(analysis)

    # Act
    result = execute_action(next_action)
    knowledge_graph.update(result)

    # Reflect
    if result.indicates_new_targets:
        objectives.add(result.new_targets)
```

### 1. Observe

The agent collects all available context:

- **Environment state**: OS, shell type, available tools, current working directory
- **Session state**: conversation history, knowledge graph (hosts, ports, vulns)
- **Target context**: user-specified target (IP, domain, URL) injected into instructions
- **Tool availability**: results from `ToolRegistry` scan, checked via `ToolAvailabilityContext`

### 2. Reason

The LLM receives a structured prompt containing:

```
User Instruction + Platform Context + Session State + Tool Inventory
```

It returns a JSON response with:

```json
{
  "needs_tools": true,
  "reasoning": "Step-by-step analysis of the request",
  "response": "Direct answer when needs_tools=false, or synthesis post-execution",
  "steps": [
    {
      "tool": "",
      "command": "exact shell command",
      "description": "What this command does and why"
    }
  ]
}
```

The reasoning step evaluates across four dimensions:

| Dimension | Consideration |
|-----------|-------------|
| **Intent** | Chat/explanation, security operation, or tool analysis |
| **Scope** | Network, web, cloud, endpoint, identity, mobile |
| **Depth** | Quick question, multi-step assessment, or deep research |
| **Risk** | Could any proposed command cause harm? |

### 3. Act

Commands from the LLM plan are executed in parallel per wave:

```python
for wave in range(max_waves):
    if not plan or not plan.steps:
        break
    raw_results = await execute_wave(plan.steps)
    plan = await llm.analyse_and_plan(wave_results)
```

Each command passes through:

1. **Permission gate** — `DangerAnalyzer` classifies destructiveness (critical/high/medium/low/safe)
2. **Input validation** — injection pattern detection (shell metacharacters, path traversal, null bytes)
3. **Shell review** — interactive `edit/run/step/cancel` prompt (when enabled)
4. **Execution** — via `safe_run_async_stream` with timeout and line-by-line output capture
5. **Secret redaction** — `SecretRedactor` strips API keys, tokens, JWTs from output

### 4. Reflect

After each wave, the LLM receives all command outputs and decides whether to:

- **Continue** (`needs_tools=true`): Generate a new plan for the next wave (e.g., found open ports → now scan for vulnerabilities)
- **Conclude** (`needs_tools=false`): Synthesize findings into a final response

Up to **5 waves** execute per instruction.

---

## Heuristic Fallback (Registry Mode)

When no LLM provider is available, the `Registry` engine provides deterministic planning:

```
Input: "scan 10.0.0.1"
  → Extract intent: "scan"
  → Extract target: "10.0.0.1"
  → Match tool: nmap (port_scan capability)
  → Build command: "nmap -sV -p 1-1000 10.0.0.1"
  → Return structured plan
```

Patterns are defined with 60+ intents across 6 shell types (bash, powershell, cmd, zsh, sh, python).

---

## Tool Selection & Dependencies

### Capability-Based Selection

The `ToolRegistry` maintains a capability index:

```python
tool_registry.find_by_capability("port_scan")
# Returns: [nmap, masscan, unicornscan, ...]
```

### Dependency Resolution

Steps are ordered into layers for parallel execution:

```
Layer 1: Recon (no deps)
Layer 2: Scan (depends on recon results)
Layer 3: Enumerate (depends on scan results)
Layer 4: Vuln Scan (depends on enumerate results)
Layer 5: Report (depends on all previous)
```

Independent steps within the same layer execute concurrently via `asyncio.gather`.

### Tool Availability Checks

Before selection, each tool's availability is evaluated via `ToolAvailabilityContext`:

- **`installed`** — binary exists on PATH
- **`auth`** — provider API key is configured
- **`config`** — configuration value is set
- **`env`** — environment variable is present
- **`always`** — always available
- Boolean expressions: `allOf`, `anyOf`

---

---

## Result Synthesis

After all waves complete, the agent:

1. Removes duplicate findings
2. Correlates related findings across tools (port from nmap + CVE from searchsploit = exploit path)
3. Assigns severity (Critical/High/Medium/Low/Info) with rationale
4. Generates actionable remediation guidance
5. Suggests next-phase testing relevant to findings

---

## Related Modules

| Module | Path | Purpose |
|--------|------|---------|
| `LLMEngineMixin` | `src/siyarix/chat/engine.py` | Multi-wave agent loop, LLM integration |
| `ToolRegistry` | `src/siyarix/registry.py` | Tool discovery and capability indexing |
| `ToolCapabilityGraph` | `src/siyarix/tool_graph.py` | Tool chaining and similarity graph |
| `ToolAvailability` | `src/siyarix/tool_availability.py` | Pre-execution availability evaluation |
| `ToolHandlers` | `src/siyarix/tool_handlers.py` | Tool-specific invocation handlers |
| `DangerAnalyzer` | `src/siyarix/security_hardening.py` | Command danger classification |
| `CompactionEngine` | `src/siyarix/compaction.py` | Context window compaction for long histories |
