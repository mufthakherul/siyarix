# Codebase Overview

Siyarix is a Python package at `src/siyarix/` organized into subpackages for agent orchestration, CLI, chat, AI providers, parsers, security, reporting, and output formatting.

## Directory Structure

```
src/siyarix/
├── __init__.py              # Public API: AgentCore, AgentMode, AgentStatus, SwarmRouter
├── __main__.py              # python -m siyarix entry point
├── main.py                  # Legacy entry, delegates to cli/
│
├── cli/
│   └── __init__.py          # Main Typer app (1782 lines) — 50+ commands, 12 command groups
│
├── chat/                    # Interactive REPL system
│   ├── __init__.py          # Exports: start_chat, SiyarixChat, ChatSession, SmartAutocomplete
│   ├── engine.py            # LLMEngineMixin (1207 lines) — agent loop, multi-wave, NL execution
│   ├── repl.py              # SiyarixChat (835 lines) — prompt_toolkit REPL with split-pane
│   ├── handlers.py          # CommandHandlersMixin (1716 lines) — 40+ slash commands
│   ├── commands.py          # CommandProfile, CommandProfileStore, slash help categories
│   ├── session.py           # ChatMessage, ChatSession — persistence, branching, context
│   ├── openai_compat.py     # Unified OpenAI-compatible adapter for all 24 providers (753 lines)
│   ├── prompts.py           # System prompt templates (SIYARIX_SYSTEM_PROMPT, COMPACT variants)
│   ├── stubs.py             # Placeholder stubs for enterprise features
│   ├── console.py           # Shared Rich Console instance
│   ├── event_stream.py      # AssistantMessageEventStream — granular streaming events
│   ├── ui.py                # SmartAutocomplete, SplitPane, ConfigPanel
│   └── platform_utils.py    # Cross-platform command definitions, shell detection
│
├── core/                    # Agent orchestration kernel
│   ├── __init__.py          # AgentCore (639 lines) — 4 modes, planners, executors, sub-agents
│   ├── pipeline.py          # CommandPipeline — chained command execution (| / then / and then)
│   └── swarm.py             # SwarmRouter — multi-agent orchestration (Recon/Exploit/Report agents)
│
├── providers/               # Multi-provider LLM abstraction layer
│   ├── __init__.py          # Re-exports: ProviderManager, ProviderStateManager, types
│   ├── manager.py           # ProviderManager singleton — registration, failover, credentials
│   ├── types.py             # ProviderType, ProviderProfile, ModelInfo, CostTier, FailoverReason
│   ├── state.py             # ProviderStateManager — cooldown, skip-known-bad cache
│   ├── usage.py             # UsageTracker — token/cost tracking per provider/model
│   └── profiles/            # 24 provider profiles (registry.py, openai.py, gemini.py, ollama.py, ...)
│
├── parsers/                 # Tool output parser subsystem
│   ├── __init__.py          # Parser protocol + ParserRegistry (auto-discovers 80+ parsers)
│   ├── nmap_parser.py       # Nmap XML/text output
│   ├── nuclei_parser.py     # Nuclei JSON output
│   ├── metasploit_parser.py # Metasploit output
│   ├── burpsuite_parser.py  # Burp Suite log snippets
│   ├── ffuf_parser.py       # FFUF JSON output
│   ├── hydra_parser.py      # Hydra output
│   └── ...                  # 80+ additional parsers for security tools
│
├── api/                     # REST API and WebSocket server
│   └── server.py            # FastAPI app — /health, /v1/* endpoints, WebSocket streaming
│
├── output/                  # Premium output engine
│   └── __init__.py          # OutputEngine — 8 formats (TABLE/JSON/YAML/CSV/HTML/XML/RAW/QUIET)
│                            # 12 themes, export to file, progress bars, live dashboards
│
├── report/                  # Security assessment report engine
│   ├── __init__.py          # ReportEngine — MARKDOWN/HTML/JSON/SARIF rendering
│   └── models.py            # Report, ReportConfig, ReportSection, ReportFormat
│
├── plugins/                 # Dynamic plugin architecture
│   └── loader.py            # PluginLoader — discovers external .py plugins at runtime
│
├── templates/               # UI templates
│   └── wizard_text.py       # Onboarding wizard text templates, ASCII art, tool lists
│
├── data/                    # Placeholder — data layer
│   └── __init__.py          # Empty
│
└── Root-level modules (core systems):
    ├── audit_log.py         # SHA-256 chained tamper-evident audit trail
    ├── bootstrap.py         # Startup initialization, env setup
    ├── branding.py          # CLI themes, color tokens, ASCII banner
    ├── cache_manager.py     # LRU cache with TTL expiration and disk persistence
    ├── compaction.py        # LLM context window optimization
    ├── compat.py            # SessionKernel, backward compatibility layer
    ├── compliance.py        # Compliance engine — 6 framework assessments
    ├── config.py            # TOML-backed settings store
    ├── connectivity.py      # Network connectivity monitoring
    ├── context.py           # Context window management and compression
    ├── credential_store.py  # AES-256-GCM encrypted credential vault
    ├── cvss_scorer.py       # CVSS 3.1 scoring engine
    ├── dlp.py               # Data Loss Prevention — secret redaction/patterns
    ├── events.py            # EventBus — typed pub/sub event system
    ├── exceptions.py        # SiyarixException hierarchy
    ├── executor.py          # BaseExecutor — plan step execution
    ├── executor_autonomous.py  # AutonomousExecutor — LLM-driven execution
    ├── executor_registry.py # RegistryExecutor — deterministic tool execution
    ├── health.py            # HealthChecker — system health assessment
    ├── internal_tools.py    # Built-in tool definitions
    ├── knowledge_graph.py   # In-memory directed graph with BFS traversal
    ├── logging_config.py    # Logging configuration
    ├── memory.py            # MemoryManager — semantic and episodic memory
    ├── metrics.py           # MetricsCollector — Prometheus-compatible metrics
    ├── models.py            # Data models, enums, dataclasses
    ├── model_aliases.py     # Model name resolution and aliasing
    ├── nlp_engine.py        # Zero-dependency NLP intent parser
    ├── notifications.py     # Notification dispatcher
    ├── offline_queue.py     # Offline request queue
    ├── offline_store.py     # Offline scan storage
    ├── onboarding.py        # First-run interactive wizard
    ├── opsec.py             # Operational security controls
    ├── performance.py       # System-aware performance tuning
    ├── permission_gate.py   # Two-stage command permission control
    ├── personas.py          # 10 security persona definitions
    ├── planner.py           # Planner router (Registry ↔ Autonomous)
    ├── planner_autonomous.py # LLM-driven plan generation
    ├── planner_registry.py  # Template-based plan generation
    ├── playbook.py          # Incident response playbook engine
    ├── provider_utils.py    # Provider utility functions
    ├── registry.py          # ToolRegistry — tool registration and resolution
    ├── response.py          # ResponseGenerator — structured AI responses
    ├── security_commands.py # Security command definitions
    ├── security_hardening.py # System security hardening
    ├── session_branching.py # JSONL tree branching sessions
    ├── session_log.py       # Session log management
    ├── shell_review.py      # Cross-platform command safety review
    ├── stealth.py           # Stealth/evasion engine
    ├── subprocess_utils.py  # Async subprocess execution helpers
    ├── threat_intel.py      # Threat intelligence — AlienVault OTX, NVD, MITRE
    ├── tool_availability.py # Tool availability evaluation
    ├── tool_call_repair.py  # LLM tool call formatting repair
    ├── tool_graph.py        # ToolCapabilityGraph — tool relationship mapping
    ├── tool_handlers.py     # Tool execution handler registry
    ├── tool_installer.py    # Cross-platform tool installer (apt/brew/winget/choco)
    ├── tool_metadata.py     # Tool metadata management
    ├── tool_models.py       # Tool capability data models
    ├── tool_version.py      # Tool version detection
    ├── validators.py        # Input validation and sanitization
    ├── webhooks.py          # Webhook dispatch
    ├── worker_pool.py       # Async worker pool with semaphore bounds
    └── workflow.py          # Workflow execution engine
```

## Key Subsystems

### Agent Orchestrator (`core/`)
`AgentCore` dispatches across four operational modes: `REGISTRY` (heuristic), `AUTONOMOUS` (LLM-driven), `HYBRID` (combined), and `INTERACTIVE` (chat). Routes intent through planners, gates, executors, and persistence layers. Supports sub-agent creation and swarm multi-agent orchestration.

### Chat & REPL (`chat/`)
Full-featured interactive shell with prompt_toolkit, split-pane layout, 40+ slash commands, context-aware autocomplete, session branching with JSONL tree format, and the `LLMEngineMixin` (1207 lines) that implements the core agent loop with multi-wave execution, streaming, and provider resolution.

### Provider Layer (`providers/`)
Abstracts 24 AI providers through a unified OpenAI-compatible adapter (`openai_compat.py`). `ProviderManager` singleton manages provider profiles, credential pooling, automatic failover with circuit breakers, exponential backoff cooldown, and usage/cost tracking.

### Parser System (`parsers/`)
`ParserRegistry` auto-discovers 80+ tool output parsers at import time via `discover()` pattern. Each parser implements the `Parser` protocol (`parse(output: str) -> list[dict]`) and handles JSON, text, or XML formats with deduplication, severity mapping, and field normalization.

### Security Layer (root-level modules)
`PermissionGate` (two-stage review), `DLP` engine (40+ secret patterns), `CredentialStore` (AES-256-GCM via keyring), `AuditLogger` (SHA-256 tamper-evident chain), `StealthEngine` (covert operations), `OPSECManager` (session isolation, secure cleanup), `InputValidator` (injection prevention), and `DangerAnalyzer` (38+ dangerous command patterns).

### Output & Reporting (`output/`, `report/`)
`OutputEngine` renders results in 8 formats (TABLE/JSON/YAML/CSV/HTML/XML/RAW/QUIET) across 12 themes. `ReportEngine` builds comprehensive security assessment reports in MARKDOWN, HTML (interactive dashboard with CSS/JS), JSON, and SARIF formats with CVSS 3.1 enrichment.

## Stub Features

The following are listed as stubs in `chat/stubs.py` and are **not fully implemented**: `CanaryTokenManager`, `CoderBridge`, `CloudScanner`, `IaCScanner`, `MobileScanner`, `IoTScanner`, `HSMService`, `ComplianceRunner` (basic exists), `SecurityImporter` (basic), `MultiModelEnsemble`, `AdversarialTester`.

## Conventions

- **Type hints**: Required on all public APIs (mypy strict mode)
- **Async**: `asyncio` throughout for concurrent operations
- **Dataclasses**: Used for structured data (findings, results, configs)
- **Error handling**: `SiyarixException` hierarchy with exit code mapping
- **Logging**: `logging.getLogger(__name__)` per module
- **Testing**: pytest with asyncio_mode=auto, 75% coverage minimum
- **Linting**: ruff with target-version py311, pre-commit hooks
