# Codebase Overview

Welcome to the Siyarix codebase. This document provides a comprehensive tour of the project structure, key subsystems, and development conventions. Siyarix is a production-grade AI-native cybersecurity orchestration platform — and its source code reflects that ambition.

## Directory Structure

Siyarix lives entirely under `src/siyarix/` as a Python package. Here is the full layout:

```
src/siyarix/
├── __init__.py              # Public API: AgentCore, AgentMode, AgentStatus, SwarmRouter
├── __main__.py              # python -m siyarix entry point
├── main.py                  # Legacy entry, delegates to cli/
│
├── cli/
│   └── __init__.py          # Main Typer app (1729 lines) — 50+ commands, 12 command groups
│
├── chat/                    # Interactive REPL system
│   ├── __init__.py          # Exports: start_chat, SiyarixChat, ChatSession, SmartAutocomplete
│   ├── engine.py            # LLMEngineMixin (1355 lines) — agent loop, multi-wave, NL execution
│   ├── repl.py              # SiyarixChat (1046 lines) — prompt_toolkit REPL with split-pane
│   ├── handlers.py          # CommandHandlersMixin (2507 lines) — 54+ slash commands
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
├── data/                    # Static data assets
│   └── cyber_tools.json     # Cybersecurity tool registry — tool names, descriptions, install hints
│
├── offline_registry/        # Offline-mode planning subsystem
│   └── __init__.py          # OfflineRegistryPlanner — heuristic planning without AI provider
│
├── deep_scan.py             # DeepScanEngine — multi-layered reconnaissance methodology
├── learning_system.py       # LearningSystem — continuous learning from past executions
├── _platform.py             # Platform detection (OS, arch, WSL, Android, iOS helpers)
├── async_utils.py           # Async utility helpers and concurrency primitives
├── compat.py                # Compatibility layer: SessionKernel, IntentRouter, ExecutionEngine (simplified)
├── workflow.py              # DAG-based workflow execution engine with conditional branching
├── model_aliases.py         # Model name resolution and aliasing across providers
├── branding.py              # CLI themes, color tokens, ASCII banner
├── notifications.py         # Notification dispatcher (Slack, Discord, email)
├── performance.py           # System-aware performance tuning and detection
├── shell_review.py          # Cross-platform command safety review
├── personas.py              # 10+ security persona definitions (auto, redteam, blueteam, dfir, etc.)
├── internal_tools.py        # Built-in tool definitions
├── subprocess_utils.py      # Async subprocess execution helpers
├── tool_call_repair.py      # LLM tool call formatting repair
├── tool_graph.py            # ToolCapabilityGraph — tool relationship mapping
├── tool_metadata.py         # Tool metadata management
├── tool_version.py          # Tool version detection
├── webhooks.py              # Webhook dispatch
├── session_branching.py     # JSONL tree branching sessions
├── session_log.py           # Session log management
├── compaction.py            # LLM context window optimization
├── connectivity.py          # Network connectivity monitoring
├── dlp.py                   # Data Loss Prevention — secret redaction/patterns
├── events.py                # EventBus — typed pub/sub event system
├── metrics.py               # MetricsCollector — Prometheus-compatible metrics
├── offline_queue.py         # Offline request queue
├── opsec.py                 # Operational security controls
├── response.py              # ResponseGenerator — structured AI responses
├── security_commands.py     # Security command definitions
├── security_hardening.py    # System security hardening
├── stealth.py               # Stealth/evasion engine
├── threat_intel.py          # Threat intelligence — AlienVault OTX, NVD, MITRE
├── validators.py            # Input validation and sanitization
├── worker_pool.py           # Async worker pool with semaphore bounds
│
└── Root-level modules (core systems continued):
    ├── audit_log.py         # SHA-256 chained tamper-evident audit trail
    ├── bootstrap.py         # Startup initialization, env setup
    ├── cache_manager.py     # LRU cache with TTL expiration and disk persistence
    ├── config.py            # TOML-backed settings store
    ├── context.py           # Context window management and compression
    ├── credential_store.py  # AES-256-GCM encrypted credential vault
    ├── cvss_scorer.py       # CVSS 3.1 scoring engine
    ├── exceptions.py        # SiyarixException hierarchy
    ├── executor.py          # BaseExecutor — plan step execution
    ├── executor_autonomous.py  # AutonomousExecutor — LLM-driven execution
    ├── executor_registry.py # RegistryExecutor — deterministic tool execution
    ├── health.py            # HealthChecker — system health assessment
    ├── knowledge_graph.py   # In-memory directed graph with BFS traversal
    ├── logging_config.py    # Logging configuration
    ├── memory.py            # MemoryManager — semantic and episodic memory
    ├── models.py            # Data models, enums, dataclasses
    ├── nlp_engine.py        # Zero-dependency NLP intent parser
    ├── offline_store.py     # Offline scan storage
    ├── onboarding.py        # First-run interactive wizard (11 steps)
    ├── permission_gate.py   # Two-stage command permission control
    ├── planner.py           # Planner router (Registry ↔ Autonomous)
    ├── planner_autonomous.py # LLM-driven plan generation
    ├── planner_registry.py  # Template-based plan generation
    ├── playbook.py          # Incident response playbook engine
    ├── provider_utils.py    # Provider utility functions
    ├── registry.py          # ToolRegistry — tool registration and resolution
    └── tool_availability.py # Tool availability evaluation
```

## Key Subsystems

### Agent Orchestrator (`core/`)

`AgentCore` dispatches across four operational modes: `REGISTRY` (heuristic), `AUTONOMOUS` (LLM-driven), `HYBRID` (combined), and `INTERACTIVE` (chat). Routes intent through planners, gates, executors, and persistence layers. Supports sub-agent creation and swarm multi-agent orchestration.

### Chat & REPL (`chat/`)

Full-featured interactive shell with prompt_toolkit, split-pane layout, 40+ slash commands, context-aware autocomplete, session branching with JSONL tree format, and the `LLMEngineMixin` (1355 lines) that implements the core agent loop with multi-wave execution, streaming, and provider resolution.

### Provider Layer (`providers/`)

Abstracts 24 AI providers through a unified OpenAI-compatible adapter (`openai_compat.py`). `ProviderManager` singleton manages provider profiles, credential pooling, automatic failover with circuit breakers, exponential backoff cooldown, and usage/cost tracking.

### Parser System (`parsers/`)

`ParserRegistry` auto-discovers 80+ tool output parsers at import time via `discover()` pattern. Each parser implements the `Parser` protocol (`parse(output: str) -> list[dict]`) and handles JSON, text, or XML formats with deduplication, severity mapping, and field normalization.

### Security Layer (root-level modules)

`PermissionGate` (two-stage review), `DLP` engine (40+ secret patterns), `CredentialStore` (AES-256-GCM via Fernet + keyring), `AuditLogger` (SHA-256 tamper-evident chain), `StealthEngine` (covert operations), `OPSECManager` (session isolation, secure cleanup), `InputValidator` (injection prevention), and `DangerAnalyzer` (38+ dangerous command patterns).

### Output & Reporting (`output/`, `report/`)

`OutputEngine` renders results in 8 formats (TABLE/JSON/YAML/CSV/HTML/XML/RAW/QUIET) across 12 themes. `ReportEngine` builds comprehensive security assessment reports in MARKDOWN, HTML (interactive dashboard with CSS/JS), JSON, and SARIF formats with CVSS 3.1 enrichment.

### Deep Scan Engine (`deep_scan.py`)

`DeepScanEngine` provides multi-layered reconnaissance with OS fingerprinting, vulnerability detection, and comprehensive reporting — chaining multiple tools and analysis passes into a structured methodology.

### Learning System (`learning_system.py`)

`LearningSystem` implements continuous learning: it monitors planner actions and builds a persistent, privacy-preserving skill library. Uses BM25-style similarity over NLP token sets with Bayesian-smoothed confidence scoring. No ML dependencies — pure Python stdlib.

### Workflow Engine (`workflow.py`)

`WorkflowEngine` provides DAG-based execution with conditional branching, pause/resume, and step-level status tracking. Supports complex multi-step security workflows with dependency-driven parallelism.

## Implemented Features (Not Stubs)

The following features are fully implemented and production-ready:

- **MultiWaveExecution** — Up to 25 plan-execute-measure waves per goal, with automatic context compaction and retry logic
- **BudgetChecking** — Configurable cost cap per session, with automatic mode degradation when limits are approached
- **SessionBranching** — JSONL tree format with `id`/`parentId` fields for forked conversations; full ancestry preservation

## Stub Features

The following are listed as stubs in `chat/stubs.py` and are **not fully implemented**: `CanaryTokenManager`, `CloudScanner`, `IaCScanner`, `MobileScanner`, `IoTScanner`, `SecurityImporter` (basic), `ComplianceRunner` (basic), `MultiModelEnsemble`, `AdversarialTester`. `HSMService` and `CoderBridge` are also present as stubs.

## Conventions

- **Type hints**: Required on all public APIs (mypy strict mode with `disallow_untyped_defs`)
- **Async**: `asyncio` throughout for concurrent operations
- **Dataclasses**: Used for structured data (findings, results, configs)
- **Error handling**: `SiyarixException` hierarchy with exit code mapping
- **Logging**: `logging.getLogger(__name__)` per module
- **Testing**: pytest with asyncio_mode=auto, 75% coverage minimum
- **Linting**: ruff with target-version py311, line-length=100, pre-commit hooks
