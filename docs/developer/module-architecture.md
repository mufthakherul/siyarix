# Module Architecture

This document explains the internal architecture of key modules in Siyarix v3.0.0.

---

## Execution Engine (`engine/executor.py`, `executor_registry.py`, `executor_autonomous.py`)

The execution engine is the central orchestrator. It operates in three modes:

| Mode | Planning | Permission | Autonomy |
|------|----------|------------|----------|
| `REGISTRY` | Tool metadata (deterministic) | Full gate | No AI required |
| `AUTONOMOUS` | LLM-driven | Minimal | Full autonomy |
| `INTEGRATED` (default) | AI-assisted | Full gate | User confirms flagged commands |

### Execution flow

1. Receives an execution plan from the planner
2. Validates each step through the permission gate
3. Executes steps with dependency-driven parallelism via `asyncio.gather()`
4. Routes tool output through the appropriate parser (114+ available)
5. Collects findings into the knowledge graph
6. Handles errors with exponential backoff with jitter

### Parallel execution

Steps in the same dependency layer run concurrently. The `worker_pool.py` bounds concurrency to prevent resource exhaustion using `asyncio.Semaphore`.

## Task Planners (`planner_registry.py`, `planner_autonomous.py`)

### Registry Planner (offline/heuristic)
Deterministic planning using the tool capability graph. Extracts intent, target, and parameters, then matches against predefined templates.

### Autonomous Planner (AI-driven)
Uses the configured AI provider to generate structured execution plans from natural language. Supports multi-call repair when the initial plan is malformed.

### Pipeline
```
User Input → Intent Extraction → Target/Parameter Parsing →
Tool Selection (by capability) → Dependency Resolution →
Provider Call (with failover) → Plan Validation → Execution
```

## Permission Gate (`permission_gate.py`)

Two-stage access control for every command:

1. **Syntax gate**: Parses command structure, checks for valid syntax, length limits, character restrictions
2. **Danger analysis**: Pattern-matches against 38 dangerous command patterns (dd, format, rm -rf, fork bomb, ping flood, privilege escalation, etc.)

Each stage returns: `ALLOW`, `DENY`, or `FLAG` (user confirmation required).

## Provider Manager (`providers/manager.py`)

Singleton managing 24 provider profiles:

- **Cloud providers**: 19 profiles (OpenAI, Gemini, Anthropic, Groq, Together, etc.) — require API keys
- **Local providers**: 5 profiles (Ollama, LM Studio, llama.cpp, vLLM, LocalAI) — no API key needed
- **Fallback**: Registry/heuristic planner — always available

### Failover chain
```
Primary → Secondary → ... → Local → Registry (heuristic)
```

Circuit breaker opens after 3 failures within 60 seconds, preventing repeated calls to failing providers. Session-disabled tracking disables failed providers for the remainder of the session.

## Credential Store (`credential_store.py`)

Encrypted vault for API keys and secrets:

- Encryption: AES-256-GCM (primary) with key rotation
- Key storage: OS system keyring via `keyring` library
- Auto-clear on session end
- Keys never stored in source code, config files, or logs

## Masking Engine (`masking.py`)

Bidirectional token masking for session output:

- Masks sensitive data before sending to cloud AI providers
- Session-scoped: masks are consistent within a session
- Bidirectional: can reverse the mask within session for local display
- Types: IPs → `10.x.x.x`, hostnames → `example.com`, credentials → `[REDACTED]`

## Knowledge Graph (`knowledge_graph.py`)

In-memory directed graph of discovered entities:

- **Nodes**: hosts, ports, services, vulnerabilities, credentials, domains
- **Edges**: relationships (runs_on, has_vuln, uses_credential)
- **Operations**: BFS shortest path, node/edge CRUD
- **Persistence**: JSON export/import

## Agentic Loop (`core/agentic_loop.py`)

The Observe-Reason-Act loop driving autonomous operations:

1. **Observe**: Collect environment state, scan results, tool outputs
2. **Reason**: Analyze findings, update knowledge graph, identify next actions
3. **Act**: Execute commands, run tools, generate reports

The loop uses the knowledge graph for tactical reflection — the AI reasons about current state before deciding the next action.

## Interactive Chat (`chat/`)

Full-featured REPL with:

- Slash command system (`/help`, `/scan`, `/run`, `/persona`, `/model`, `/command`, etc.)
- Multi-turn conversation with context retention
- Tab completion for commands and targets
- Command history (SQLite-backed)
- Session save/load
- Persona switching mid-session
- Provider switching at runtime
- Command review toggle
- Real-time Rich notification panels

## Experience Intelligence (`xi/`)

Adaptive learning subsystem:

| Component | Function |
|-----------|----------|
| `ContextTracker` | 8 operation phases, target inventory, tool history, finding accumulation |
| `SkillProfiler` | 4 experience levels (beginner → expert) based on tool diversity, command volume, error rate |
| `Predictor` | Next-action prediction based on phase, tool follow-up, findings, learned patterns |
| `XICoreService` | Recommendation engine combining all XI components |
