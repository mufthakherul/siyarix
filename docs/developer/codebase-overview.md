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
├── providers/               # 24 AI provider profiles (Adapters)
│
├── parsers/                 # Tool output parsers (114+ tools)
│   ├── nmap_parser.py       # Nmap XML output
│   ├── masscan_parser.py    # Masscan
│   ├── metasploit_parser.py # Metasploit
│   ├── nuclei_parser.py     # Nuclei
│   ├── burpsuite_parser.py  # Burp Suite
│   ├── hydra_parser.py      # Hydra
│   ├── ffuf_parser.py       # FFUF
│   ├── gobuster_parser.py   # Gobuster
│   ├── nikto_parser.py      # Nikto
│   ├── sqlmap_parser.py     # SQLMap
│   ├── zaproxy_parser.py    # ZAP
│   ├── shodan_parser.py     # Shodan
│   ├── subfinder_parser.py  # Subfinder
│   ├── amass_parser.py      # Amass
│   ├── ... (114+ total)
│   └── __init__.py           # ParserRegistry with protocol
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
├── providers/               # AI provider abstraction (24 profiles)
├── planner_*.py             # Task planners (registry, autonomous)
├── executor_*.py            # Executors (registry, autonomous)
├── registry.py              # Tool discovery (100+ tools)
├── credential_store.py      # Encrypted credential vault (AES-256-GCM)
├── audit_log.py             # Tamper-evident SHA-256 chained logging
├── knowledge_graph.py       # In-memory relationship graph
├── masking.py               # Bidirectional token masking
├── permission_gate.py       # Two-stage permission control (38 patterns)
├── playbook.py              # Incident response playbooks
├── health.py                # System health checks
├── metrics.py               # Performance metrics
├── compliance.py            # Compliance framework assessments (6 frameworks)
├── threat_intel.py          # MITRE ATT&CK, MISP/STIX feed ingestion
├── personas.py              # Persona system (10 security mindsets)
├── stealth.py               # Stealth/evasion engine
├── opsec.py                 # Operational security controls
├── session_branching.py     # Session branching for concurrent workflows
├── dlp.py                   # Data loss prevention patterns
├── connectivity.py          # Network connectivity checks
├── cvss_scorer.py           # CVSS scoring engine
├── notifications.py         # Notification dispatcher (Slack, Discord)
├── webhooks.py              # Webhook sender
├── worker_pool.py           # Parallel async worker pool
├── cache_manager.py         # LRU cache with TTL
├── offline_store.py         # SQLite offline data store
├── offline_queue.py         # Offline task queue
├── compaction.py            # Session compaction
├── onboarding.py            # First-run setup wizard
├── branding.py              # CLI branding, themes, banner
├── nlp_engine.py            # NLP engine for intent parsing
├── tool_installer.py        # Tool installer (apt, brew, winget, pip)
└── ... (50+ additional modules)
```

## Key subsystems

### Core kernel (`core/`)
The foundation layer: event bus for pub/sub communication, intent router for command dispatch, mode dispatcher for 9 interaction modes, session kernel for state management, agentic loop for Observe-Reason-Act cycle, and command pipeline for chained execution.

### Execution engine (`engine/`)
Processes plans into executed commands. Handles tool selection, parallel execution, output parsing, error recovery with exponential backoff, permission gating, and context window compression.

### AI provider layer (`providers/`, `planner*.py`)
Abstraction over 24 provider profiles with `ProviderManager` singleton, automatic failover, circuit breakers, session-disabled provider tracking, and heuristic fallback when no provider is available.

### Tool system (`registry.py`, `tool_*.py`, `parsers/`)
Discovers 100+ security tools across platforms with capability graph and version detection. 114+ parsers extract structured findings from tool output (nmap, nuclei, masscan, metasploit, burpsuite, etc.).

### Experience Intelligence (`xi/`)
Adaptive learning subsystem: context tracker (8 operation phases), skill profiler (4 experience levels), next-action predictor, and recommendation engine.

### Telemetry & Observability (`telemetry/`)
OpenTelemetry collector for distributed tracing, SIEM forwarding to Splunk/ELK, Prometheus-compatible metrics, performance monitoring.

### Security modules
Credential store (AES-256-GCM encrypted vault), masking engine (bidirectional token redaction), permission gate (two-stage access control), audit log (SHA-256 tamper-evident chain), knowledge graph (in-memory relationship modeling with BFS traversal).

## Conventions

- **Type hints**: Required on all public APIs
- **Async**: `asyncio` throughout for concurrent operations
- **Dataclasses**: Used for structured data (findings, results, configs)
- **Error handling**: `SiyarixException` hierarchy with exit code mapping
- **Logging**: `logging.getLogger(__name__)` per module
