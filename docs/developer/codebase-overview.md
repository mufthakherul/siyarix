# 🗺️ Codebase Overview

Welcome to the Siyarix codebase! This document serves as your compass, providing a comprehensive tour of our project structure, core subsystems, and development conventions. Siyarix is designed as a production-grade, AI-native cybersecurity orchestration platform—and our source code reflects that high standard.

> [!TIP]
> If you are new to the codebase, we highly recommend starting with the **Agent Orchestrator (`core/`)** and **Interactive Chat (`chat/`)** modules, as they form the heart of the user experience!

## 📂 Directory Structure

Siyarix lives entirely under the `src/siyarix/` directory as a cohesive Python package. Here is the full layout:

```text
src/siyarix/
├── __init__.py              # Public API (AgentCore, AgentMode, AgentStatus, SwarmRouter)
├── __main__.py              # Entry point for `python -m siyarix`
├── main.py                  # Legacy entry point (delegates to cli/)
│
├── cli/
│   └── __init__.py          # Main Typer CLI app (50+ commands across 12 groups)
│
├── chat/                    # 💬 Interactive REPL system
│   ├── engine.py            # LLMEngineMixin: The core agent loop & natural language execution
│   ├── repl.py              # SiyarixChat: prompt_toolkit REPL with a beautiful split-pane UI
│   ├── handlers.py          # 54+ slash command handlers
│   ├── openai_compat.py     # Unified adapter supporting 24+ AI providers!
│   └── ...                  # Session management, streaming events, and UI helpers
│
├── core/                    # 🧠 Agent Orchestration Kernel
│   ├── __init__.py          # AgentCore: manages modes, planners, and sub-agents
│   ├── pipeline.py          # CommandPipeline: executes chained commands
│   └── swarm.py             # SwarmRouter: multi-agent coordination (Recon/Exploit/Report)
│
├── providers/               # ☁️ Multi-Provider LLM Abstraction Layer
│   ├── manager.py           # Registration, failover logic, and credential management
│   ├── state.py             # Cooldowns and skip-known-bad caching
│   └── profiles/            # 24 individual provider profiles (OpenAI, Gemini, Ollama, etc.)
│
├── parsers/                 # 🔍 Tool Output Parser Subsystem
│   ├── __init__.py          # ParserRegistry (auto-discovers 80+ parsers!)
│   ├── nmap_parser.py       # Nmap XML/text parser
│   └── ...                  # Parsers for Nuclei, Metasploit, BurpSuite, FFUF, etc.
│
├── output/                  # 🎨 Premium Output Engine
│   └── __init__.py          # Renders 8 formats (JSON, YAML, HTML, etc.) in 12 themes
│
├── report/                  # 📊 Security Assessment Reporting
│   └── __init__.py          # Generates reports in MARKDOWN, HTML, JSON, and SARIF
│
├── plugins/                 # 🔌 Dynamic Plugin Architecture
├── templates/               # 📝 UI Templates and ASCII Art
├── data/                    # 🗄️ Static assets (like the `cyber_tools.json` registry)
├── offline_registry/        # 📴 Offline heuristic planning subsystem
│
└── Root-Level Modules:
    ├── audit_log.py         # SHA-256 chained, tamper-evident audit trails
    ├── credential_store.py  # AES-256-GCM encrypted credential vault
    ├── deep_scan.py         # Multi-layered reconnaissance engine
    ├── learning_system.py   # Continuous learning from past executions
    ├── opsec.py             # Operational security controls
    ├── permission_gate.py   # Two-stage command permission control
    ├── workflow.py          # DAG-based execution engine
    └── ...                  # Dozens of other specialized modules!
```

## 🏗️ Key Subsystems

### 🧠 Agent Orchestrator (`core/`)
`AgentCore` is the brain of Siyarix. It dispatches tasks across four operational modes:
- `REGISTRY` (heuristic-based)
- `AUTONOMOUS` (LLM-driven)
- `HYBRID` (combined)
- `INTERACTIVE` (chat-driven)

It routes intent through planners, permission gates, and executors, while supporting sub-agent creation and "swarm" multi-agent orchestration.

### 💬 Chat & REPL (`chat/`)
Our fully-featured interactive shell is built on `prompt_toolkit`. It boasts a split-pane layout, over 40 slash commands, and context-aware autocomplete. The `LLMEngineMixin` implements our core agent loop, supporting multi-wave execution and real-time streaming.

### ☁️ Provider Layer (`providers/`)
We abstract 24 distinct AI providers through a unified, OpenAI-compatible adapter (`openai_compat.py`). The `ProviderManager` handles automatic failover with circuit breakers, exponential backoff, and usage/cost tracking, ensuring Siyarix stays online even if a specific API goes down.

### 🔍 Parser System (`parsers/`)
The `ParserRegistry` automatically discovers over 80 tool parsers at import time. Each parser implements the `Parser` protocol, ingesting JSON, text, or XML formats to normalize data and map severities perfectly.

### 🛡️ Security Layer (Root Modules)
Security is paramount. Our robust security layer includes:
- **PermissionGate**: A two-stage review for executing commands.
- **DLP Engine**: Masks over 40 patterns of sensitive data.
- **CredentialStore**: Secures API keys using AES-256-GCM.
- **AuditLogger**: Maintains a SHA-256 tamper-evident chain of actions.

### 🎨 Output & Reporting (`output/`, `report/`)
Siyarix looks as good as it works. The `OutputEngine` supports 8 formats across 12 distinct themes. When it's time to deliver results, the `ReportEngine` compiles comprehensive security assessments (Markdown, HTML dashboards, JSON, SARIF) enriched with CVSS 3.1 scoring.

### 🔬 Advanced Engines
- **Deep Scan Engine (`deep_scan.py`)**: Multi-layered recon combining OS fingerprinting, vulnerability detection, and automated methodology.
- **Learning System (`learning_system.py`)**: A privacy-preserving skill library that learns from past executions using BM25-style similarity and Bayesian confidence scoring—zero ML dependencies required!
- **Workflow Engine (`workflow.py`)**: A DAG-based engine supporting conditional branching, pausing, and resuming complex security workflows.

> [!IMPORTANT]
> **Implemented Features vs. Stubs**
> Siyarix has fully implemented production-ready features like **MultiWaveExecution** (up to 25 plan-execute-measure waves), **BudgetChecking**, and **SessionBranching**. However, note that some enterprise features (e.g., `CloudScanner`, `MobileScanner`, `AdversarialTester`) listed in `chat/stubs.py` are currently placeholders designed for future expansion.

## 📏 Development Conventions

To maintain a pristine and predictable codebase, we strictly adhere to the following standards:

- **Type Hints:** Required on all public APIs. We run MyPy in strict mode (`disallow_untyped_defs`).
- **Async First:** `asyncio` is used extensively for all concurrent operations.
- **Structured Data:** We heavily utilize Python `dataclasses` for representing findings, results, and configs.
- **Error Handling:** Always use the `SiyarixException` hierarchy. Bare `except:` blocks are strictly forbidden.
- **Logging:** Standard Python logging (`logging.getLogger(__name__)`) is used per module.
- **Testing:** We rely on `pytest` with `asyncio_mode=auto` and mandate a minimum of **75% code coverage**.
- **Linting:** We format and lint with **Ruff** (targeting Python 3.11, line-length=100) and enforce checks via pre-commit hooks.
