# Module Architecture

This document describes the internal architecture of key Siyarix v3.0.0 modules — how they interact, their data flows, and design patterns.

## Execution Engine (`executor.py`, `executor_registry.py`, `executor_autonomous.py`)

The execution engine operates in three modes, dispatched by the planner:

| Mode | Planner | Permission | Autonomy | Use Case |
|------|---------|------------|----------|----------|
| `REGISTRY` | RegistryPlanner (template) | Full gate | None | Offline, deterministic |
| `AUTONOMOUS` | AutonomousPlanner (LLM) | Minimal | Full | Unattended operation |
| `HYBRID` (default) | Combined | Full gate | User confirmation | Interactive security work |

### Execution Flow

1. Planner produces `ExecutionPlan` with ordered `ExecutionStep` objects
2. Each step validated through `PermissionGate` (ALLOW/DENY/REVIEW)
3. Steps execute with dependency-driven parallelism via `asyncio.gather()`
4. Tool output routed through `ParserRegistry.get(tool_name).parse(output)`
5. Structured findings ingested into `KnowledgeGraph`
6. Errors handled with exponential backoff via `ProviderStateManager`

### Worker Pool

`worker_pool.py` bounds concurrency using `asyncio.Semaphore`, preventing resource exhaustion when executing parallel tool chains. Default max concurrent tools is configurable via `default_parallel` setting.

## Task Planners (`planner.py`, `planner_registry.py`, `planner_autonomous.py`)

### Planner Router (`planner.py`)
Routes between two planner implementations based on mode and provider availability. Falls back to registry planning when no AI provider is reachable.

### Registry Planner (`planner_registry.py`)
Deterministic planning using `PlannerRegistry`, a template store that maps tool capabilities to execution plans. Uses intent classification, keyword matching, and parameter extraction. No AI dependency — always available.

### Autonomous Planner (`planner_autonomous.py`)
LLM-driven planning that generates structured execution plans from natural language goals. Uses `ProviderManager` for provider resolution with failover. Supports multi-call repair when initial plan is malformed (via `ToolCallRepair`).

### Pipeline
```
User Input → IntentRouter → Intent Extraction → Target/Parameter Parsing →
Planner Selection (by mode/provider) → Plan Generation →
Plan Validation → Permission Gate → Execution → Result Processing
```

## Permission Gate (`permission_gate.py`)

Two-stage access control executed before every command:

1. **Syntax Gate**: Validates command structure, length limits, character restrictions, shell injection patterns
2. **Danger Analysis**: Pattern-matches against 38+ dangerous command categories (disk destruction, fork bombs, network floods, privilege escalation, credential exfiltration, etc.)

Each stage returns one of: `ALLOW` (pass), `DENY` (block with reason), or `REVIEW` (require user confirmation). The gate integrates with `DLP` engine for data exfiltration detection and `InputValidator` for injection prevention.

## Provider Manager (`providers/manager.py`)

Singleton managing 24 provider profiles through a unified interface:

- **Cloud providers**: 19 profiles (OpenAI, Anthropic, Gemini, Groq, Together, DeepSeek, Mistral, OpenRouter, Perplexity, xAI, Cerebras, Fireworks, HuggingFace, MiniMax, Moonshot, NVIDIA, Azure, OpenCodeZen, Z.AI) — require API keys
- **Local providers**: 5 profiles (Ollama, LM Studio, llama.cpp, vLLM, LocalAI) — no API key, auto-start support
- **Fallback**: Registry (heuristic planner) — always available, no AI required

### Failover Chain
```
Primary Provider → Secondary → ... → Local Provider → Registry (heuristic)
```

Circuit breaker opens after 3 failures within 60 seconds. `ProviderStateManager` tracks per-provider cooldown with exponential backoff (30s → 60s → 300s). Skip-known-bad cache prevents retrying failing providers within a session.

## Credential Store (`credential_store.py`)

Encrypted vault for API keys and secrets:

- Encryption: AES-256-GCM with 32-byte key and 12-byte nonce
- Key storage: OS system keyring via `keyring` library
- File fallback: AES-256-GCM encrypted JSON file in `~/.siyarix/credentials.json` (Fernet-compatible)
- Key rotation: `siyarix auth rotate` re-encrypts all credentials with a new key
- Auto-clear: Credentials cleared from memory on session end
- Security: Keys never written to source code, config files, logs, or debug output

## DLP Engine (`dlp.py`)

Data Loss Prevention with bidirectional token masking:

- Masks sensitive data before sending to cloud AI providers (40+ regex patterns)
- Session-scoped: masks are consistent within a session
- Bidirectional: can reverse masks for local display
- Pattern types: IP addresses, hostnames, email addresses, API keys, JWT tokens, SSH keys, passwords, credit cards, AWS keys, Slack tokens, GitHub tokens, private keys

## Knowledge Graph (`knowledge_graph.py`)

In-memory directed graph of discovered entities:

- **Nodes**: hosts, ports, services, vulnerabilities, credentials, domains, findings
- **Edges**: relationships (runs_on, has_vulnerability, uses_credential, resolves_to)
- **Operations**: add_node, add_edge, find_neighbors, bfs_shortest_path, node/edge CRUD, find_by_label, find_by_type
- **Traversal**: BFS, DFS, shortest path analysis
- **Persistence**: JSON export/import with full graph serialization
- **Integration**: ReportEngine queries KG for evidence and relationship mapping

## Agent Core (`core/__init__.py`)

`AgentCore` is the central orchestrator (639 lines) that manages the full agent lifecycle:

1. **Start/Shutdown**: Initialize sub-systems, providers, memory, context, stealth
2. **Goal Execution**: `execute_goal()` routes to mode-specific execution (`_execute_registry`, `_execute_autonomous`, `_execute_hybrid`, `_execute_interactive`)
3. **Multi-Wave**: `execute_multi_wave()` for complex objectives requiring iterative refinement
4. **Sub-Agents**: `create_subagent()` / `execute_subagent()` for hierarchical task decomposition
5. **Swarm**: Integrates with `SwarmRouter` for multi-agent campaigns (recon → exploit → report)
6. **Observation**: Tracks results, budget, and goal completion status

## Event Bus (`events.py`)

In-process publish/subscribe system:

- `EventBus` singleton with typed event dispatch
- Events include: finding discovered, plan created, step executed, error occurred, session created
- Supports multiple subscribers per event type
- Used by: `AuditLogger`, `Notifications`, `MetricsCollector`, `SessionLog`
- Zero external dependencies — pure Python implementation

## Interactive Chat (`chat/`)

Full-featured REPL with:

- 40+ slash commands via `CommandHandlersMixin` (help, scan, run, model, provider, theme, opsec, intel, etc.)
- Multi-turn conversation with context retention and compression
- `SmartAutocomplete` for context-aware tab completion (commands, tools, models, providers, paths)
- Session branching with JSONL tree format via `BranchingSession`
- Persona switching mid-session
- Provider switching at runtime
- Command review toggle
- Real-time Rich notification panels
- `SplitPane` for timeline, metrics, cheatsheet views

## LLM Engine (`chat/engine.py`)

The `LLMEngineMixin` (1207 lines) implements the core AI interaction loop:

1. **Provider Resolution**: Selects provider via `ProviderManager` with failover
2. **Context Building**: Builds system prompt with persona, platform context, tool availability
3. **Agent Execution**: `_execute_agent()` runs observe-reason-act loop with up to 5 waves
4. **Multi-Wave**: Each wave executes LLM calls, parallel tool execution, and LLM synthesis
5. **Streaming**: `AssistantMessageEventStream` provides granular per-block events (text, thinking, tool calls)
6. **Retry**: Automatic retry with compaction for long contexts
7. **Local Provider Auto-Start**: Detects and starts Ollama/llama.cpp if configured

## Output Engine (`output/__init__.py`)

Premium output rendering with 8 formats and 12 themes:

- **Formats**: TABLE (Rich), JSON, YAML, CSV, HTML, XML, RAW, QUIET
- **Themes**: CYBER_NOIR, MATRIX, BLOODMOON, ARCTIC, GOLDENROD, ECLIPSE, SYNTHWAVE, DARK, LIGHT, NEON, MINIMAL, DEFAULT
- **Features**: Progress bars, live dashboards, export to file, gradient banners, syntax highlighting
- **Graceful degradation**: Falls back to plain print when Rich is unavailable

## Report Engine (`report/__init__.py`)

Comprehensive security report generation:

- **Input**: Raw findings list or `KnowledgeGraph` query
- **Sections**: Executive summary, methodology, findings (by severity), evidence, remediation, appendix
- **Formats**: MARKDOWN (structured), HTML (interactive dashboard with CSS/JS), JSON (programmatic), SARIF (tool interoperability)
- **CVSS**: Integrated `CVSSScorer` for vulnerability scoring enrichment
- **Configuration**: Title, author, company, section toggles, scoring options

## Swarm Architecture (`core/swarm.py`)

Multi-agent orchestration for complex campaigns:

- **SpecializedAgent** base class with `analyze()` async method
- **Agent Roles**: `ReconAgent` (discovery), `ExploitAgent` (vulnerability validation), `ReportAgent` (findings synthesis)
- **SwarmRouter**: Task decomposition, agent dispatch, result aggregation
- **Campaign Flow**: Recon → Exploit → Report with handoff between phases
