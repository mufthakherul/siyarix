# Module Architecture

This document explains the internal architecture of key modules.

## Execution engine (`engine/executor.py`)

The execution engine is the central orchestrator. It:

1. Receives an execution plan from the planner
2. Validates each step through the permission gate
3. Executes steps with dependency-driven parallelism
4. Routes tool output through the appropriate parser
5. Collects findings into the session context
6. Handles errors with exponential backoff

### Execution modes

| Mode | Behavior |
|------|----------|
| `REGISTRY` | Uses tool metadata for deterministic execution |
| `AUTONOMOUS` | Full AI autonomy, no user confirmation |
| `INTEGRATED` | AI planning with safety gates |

### Parallel execution

Steps that don't depend on each other run concurrently via `asyncio.gather()`. The `worker_pool.py` bounds concurrency to prevent resource exhaustion.

## Task planner (`planner.py`)

Converts natural language into structured execution plans.

### Pipeline

1. User input received
2. Intent extracted (scan, recon, exploit, etc.)
3. Target/parameters parsed
4. Tools selected from registry based on capability
5. Steps ordered with dependency resolution
6. Circuit breaker checked per provider
7. Provider called for plan generation
8. Heuristic fallback if no provider available

### Circuit breaker

Per-provider circuit breaker tracks failures:

- 3 failures within 60s → circuit OPEN
- OPEN stays for 60s, then HALF-OPEN
- On HALF-OPEN success → CLOSED
- On HALF-OPEN failure → OPEN again

## Permission gate (`permission_gate.py`)

Three-stage access control for every command:

1. **Syntax gate**: Parses the command, checks for valid structure
2. **Danger analysis**: Pattern-matches against 38 dangerous command patterns (dd, format, rm -rf, etc.)
3. **Persona ACL**: Checks if the current persona allows the tool/command

Each stage can allow, deny, or flag for user confirmation.

## Credential store (`credential_store.py`)

Encrypted vault for API keys and secrets.

- Encryption: AES-256-GCM (primary) or Fernet (fallback)
- Key storage: system keyring via `keyring` library
- Optional KMS integration for envelope encryption
- Key rotation support
- Import/export functionality

## Masking engine (`masking.py`)

Bidirectional token masking for session output.

- Masks sensitive data: JWT tokens, API keys, credentials, IP addresses
- Session-scoped: masks are consistent within a session
- Bidirectional: can reverse the mask for logging/reporting (within session)

## Knowledge graph (`knowledge_graph.py`)

In-memory graph of discovered entities.

- **Nodes**: hosts, ports, services, vulnerabilities, credentials, domains
- **Edges**: relationships between entities (runs_on, has_vuln, uses_cred)
- **Operations**: BFS shortest path, add/update/remove nodes and edges
- **Persistence**: JSON export/import

## Agentic loop (`core/agentic_loop.py`)

The Observe-Reason-Act loop that drives autonomous operation:

1. **Observe**: Collect environment state, scan results, tool outputs
2. **Reason**: Analyze findings, update knowledge graph, identify next actions
3. **Act**: Execute commands, run tools, generate reports

The loop uses the knowledge graph for tactical reflection — the AI reasons about the current state before deciding the next action.

## Interactive chat (`chat.py`)

Full-featured REPL (2982 lines) with:

- Slash command system (`/help`, `/scan`, `/run`, etc.)
- Multi-turn conversation with context retention
- Tab completion for commands and targets
- Command history (SQLite-backed)
- Session save/load
- Persona switching mid-session
- Real-time Rich notification panels
