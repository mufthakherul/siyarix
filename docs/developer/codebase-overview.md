# Codebase Overview

Siyarix is structured as a Python package at `src/siyarix/` with subpackages for core systems, engine, security, AI, UI, and parsers.

## Directory structure

```
src/siyarix/
├── __init__.py              # Public API re-exports
├── __main__.py              # python -m siyarix support
├── main.py                  # CLI entry point (Typer app, 50+ commands)
├── chat.py                  # Interactive chat REPL
├── config.py                # Settings store (TOML-backed)
│
├── core/                    # Kernel primitives
│   ├── agentic_loop.py      # Observe-Reason-Act loop
│   ├── event_bus.py         # In-process pub/sub events
│   ├── intent_router.py     # Semantic command routing
│   ├── mode_dispatcher.py   # 9 interaction modes
│   ├── pipeline.py          # Command chaining
│   └── session_kernel.py    # Session state & operation cards
│
├── engine/                  # Execution engine
│   ├── context.py           # Context window compression
│   ├── executor.py          # Core execution engine (plan-execute loop)
│   ├── providers.py         # AI provider setup & preference chains
│   ├── recovery.py          # Error recovery with backoff
│   ├── safety.py            # Permission gating integration
│   └── steps.py             # Execution modes & result aggregation
│
├── security/                # Security analysis
│   └── attack_path.py       # Attack path discovery from knowledge graph
│
├── ai/                      # (planning to split provider adapters)
│
├── parsers/                 # Tool output parsers (18+ tools)
│   ├── nmap_parser.py       # Nmap XML output
│   ├── masscan_parser.py    # Masscan
│   ├── metasploit_parser.py # Metasploit
│   ├── nuclei_parser.py     # Nuclei
│   ├── burpsuite_parser.py  # Burp Suite
│   ├── hydra_parser.py      # Hydra
│   ├── ffuf_parser.py       # FFUF
│   └── ... (18 total)
│
├── xi/                      # Experience Intelligence
│   ├── context_tracker.py   # Session context tracking
│   ├── predictor.py         # Command sequence prediction
│   ├── service.py           # Recommendation engine
│   └── skill_profiler.py    # User skill profiling
│
├── telemetry/               # Observability
│   ├── opentelemetry.py     # OpenTelemetry collector
│   └── siem.py              # SIEM forwarding (Splunk/ELK)
│
├── orchestration/           # Workflow runtime
│   └── workflow_runtime.py  # DAG-based workflow execution
│
├── ux/                      # User experience
│   ├── config_panel.py      # TUI configuration panel
│   ├── wizard.py            # Onboarding wizard
│   ├── split_pane.py        # Split-pane component
│   ├── command_palette.py   # Command palette
│   └── autocomplete.py      # Smart autocomplete
│
├── visualizations/          # Data visualization
│   └── attack_graph.py      # Attack graph rendering
│
├── providers.py             # AI provider abstraction (10 providers)
├── planner.py               # Task planner (NL → structured commands)
├── tool_registry.py         # Tool discovery (100+ tools)
├── credential_store.py      # Encrypted credential vault
├── audit_log.py             # Tamper-evident audit logging
├── knowledge_graph.py       # In-memory relationship graph
├── masking.py               # Bidirectional token masking
├── permission_gate.py       # Three-stage permission control
├── playbook_engine.py       # Incident response playbooks
├── health.py                # System health checks
├── metrics.py               # Performance metrics
└── ... (30+ additional modules)
```

## Key subsystems

### Core kernel (`core/`)
The foundation layer: event bus for pub/sub communication, intent router for command dispatch, mode dispatcher for 9 interaction modes, session kernel for state management, and the agentic loop for the Observe-Reason-Act cycle.

### Execution engine (`engine/`)
Processes plans into executed commands. Handles tool selection, parallel execution, output parsing, error recovery with exponential backoff, and permission gating.

### AI provider layer (`providers.py`, `planner.py`)
Abstraction over 10 AI providers with automatic failover, circuit breakers, and heuristic fallback when no provider is available.

### Tool system (`tool_registry.py`, `parsers/`)
Discovers 100+ security tools across platforms. Each tool has metadata for invocation, capability tagging, and output parsing. Parsers extract structured findings from tool output.

### Security modules
Credential store (encrypted vault), masking engine (token redaction), permission gate (three-stage access control), audit log (tamper-evident chain), knowledge graph (relationship modeling).

## Conventions

- **Type hints**: Required on all public APIs
- **Async**: `asyncio` throughout for concurrent operations
- **Dataclasses**: Used for structured data (findings, results, configs)
- **Error handling**: `SiyarixException` hierarchy with exit code mapping
- **Logging**: `logging.getLogger(__name__)` per module
