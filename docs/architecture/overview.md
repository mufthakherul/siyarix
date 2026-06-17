# System Overview

Siyarix is an AI-native cybersecurity operations platform. It combines a multi-provider AI planning layer with a comprehensive tool execution engine, all exposed through a CLI-first interface.

## High-level architecture

```
User (CLI / Chat / Pipeline)
        │
        ▼
┌───────────────────────────┐
│   Interaction Modes       │
│  (CLI, Chat, Pipeline,    │
│   Agent, Workflow, TUI)   │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│   Intent Router           │
│  (exact → regex → keyword │
│   → LLM fallback)         │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│   Task Planner            │
│  (AI or heuristic)        │
│  + Circuit Breakers       │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│   Permission Gate         │
│  (syntax → danger → ACL)  │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│   Execution Engine        │
│  (parallel step exec)     │
│  + Tool Registry          │
│  + Tool Parsers           │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│   Output & Reporting      │
│  (table/JSON/YAML/CSV,    │
│   audit log, session log) │
└───────────────────────────┘
```

## Core design principles

1. **CLI-first**: All functionality is accessible from the command line. No GUI dependency.
2. **AI-native**: AI planning is the default path, with graceful degradation to heuristics.
3. **Provider-agnostic**: No hard dependency on any single AI provider. 24 provider profiles supported, from cloud to local.
4. **Offline-capable**: The system works fully offline using heuristic fallback and local models (Ollama, LM Studio).
5. **Safety-gated**: Every command passes through a three-stage permission gate before execution.
6. **Extensible**: Tool parsers, providers, personas, and workflows are all pluggable.

## Key subsystems

| Subsystem | Location | Purpose |
|-----------|----------|---------|
| CLI entry point | `cli/` | Typer app and 50+ command definitions |
| Interactive chat | `chat/` | REPL with slash commands, multi-turn conversation |
| Core systems | `core/` | Intent router, mode dispatcher, session kernel, agentic loop, pipeline, event bus |
| Execution engine | `engine/` | Plan execution, safety, recovery, context management |
| AI provider layer | `providers/` | 24 provider profiles with singleton Manager |
| Task planners | `planner*.py` | NL-to-plan conversion (registry, autonomous) |
| Tool registry | `registry.py` | Tool discovery, capability graph, metadata |
| Parsers | `parsers/` | 114+ tool output parsers |
| Security | `credential_store.py`, `permission_gate.py`, `audit_log.py` | Security controls |
| Persistence | `offline_store.py`, `session_log.py`, `memory.py` | SQLite, cache, memory |

## Data flow

```
Input (text) → Intent Router → Task Planner → Permission Gate → Execution Engine → Output
                                                      │
                                                      ▼
                                               Knowledge Graph
                                               (in-memory state)
```

The knowledge graph maintains discovered entities (hosts, ports, vulns, credentials) across the session, enabling the agent to reason about relationships and plan multi-step operations.

## Scalability

- **Worker pool** (`worker_pool.py`): Bounded asyncio worker pool for concurrent operations
- **Cache** (`cache_manager.py`): LRU cache with TTL for tool outputs and provider responses
- **Offline store** (`offline_store.py`): SQLite with WAL mode for concurrent reads
- **Docker**: Multi-stage Dockerfile + Docker Compose with worker, dashboard, Redis, OpenTelemetry
- **REST API**: FastAPI server with JWT auth, scan/chat endpoints, WebSocket streaming
