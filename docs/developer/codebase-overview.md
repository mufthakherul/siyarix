# 🗺️ Codebase Overview

Welcome to the Siyarix codebase! This document serves as a quick tour of the project structure and core modules. Siyarix started as a personal passion project to explore AI-native orchestration, and it's continuously growing thanks to active development.

!!! tip
    If you are new to the codebase, I recommend starting with the **Agent Orchestrator (`core/`)** and **Interactive Chat (`chat/`)** modules, as they form the core experience!

## 📂 Directory Structure

Siyarix lives under the `src/siyarix/` directory. Here is the layout:

```text
src/siyarix/
├── __init__.py              # Public API
├── __main__.py              # Entry point for `python -m siyarix`
├── main.py                  # Legacy entry point
│
├── cli/
│   └── __init__.py          # Main Typer CLI app
│
├── chat/                    # 💬 Interactive REPL system
│   ├── engine.py            # LLMEngineMixin
│   ├── repl.py              # SiyarixChat: prompt_toolkit REPL
│   ├── handlers.py          # Slash command handlers
│   ├── openai_compat.py     # Adapter for AI providers
│   └── ...
│
├── core/                    # 🧠 Agent Orchestration Kernel
│   ├── __init__.py          # AgentCore
│   ├── pipeline.py          # CommandPipeline
│   └── swarm.py             # SwarmRouter
│
├── providers/               # ☁️ Multi-Provider LLM Abstraction Layer
│   ├── manager.py           # Registration and management
│   ├── state.py             # Cooldowns and caching
│   └── profiles/            # Provider profiles (OpenAI, Gemini, Ollama, etc.)
│
├── parsers/                 # 🔍 Tool Output Parser Subsystem
│   ├── __init__.py          # ParserRegistry
│   ├── nmap_parser.py       # Nmap XML/text parser
│   └── ...
│
├── output/                  # 🎨 Output Engine
│   └── __init__.py          # Renders formats (JSON, YAML, HTML, etc.)
│
├── report/                  # 📊 Reporting
│   └── __init__.py          # Generates reports in MARKDOWN, HTML, JSON
│
├── plugins/                 # 🔌 Dynamic Plugin Architecture
├── templates/               # 📝 UI Templates and ASCII Art
├── data/                    # 🗄️ Static assets
├── offline_registry/        # 📴 Offline heuristic planning subsystem
│
└── Root-Level Modules:
    ├── audit_log.py         # Audit trails
    ├── credential_store.py  # Encrypted credential vault
    ├── deep_scan.py         # Reconnaissance engine
    ├── learning_system.py   # Basic learning from executions
    ├── opsec.py             # Basic OPSEC controls
    ├── permission_gate.py   # Command permission control
    ├── workflow.py          # Workflow engine
    └── ...
```

## 🏗️ Key Subsystems

### 🧠 Agent Orchestrator (`core/`)
`AgentCore` is the brain of Siyarix. It dispatches tasks across four operational modes:
- `REGISTRY` (heuristic-based)
- `AUTONOMOUS` (LLM-driven)
- `HYBRID` (combined)
- `INTERACTIVE` (chat-driven)

### 💬 Chat & REPL (`chat/`)
Our interactive shell is built on `prompt_toolkit`, featuring a split-pane layout and context-aware autocomplete. The `LLMEngineMixin` runs the agent loop.

### ☁️ Provider Layer (`providers/`)
Siyarix abstracts various AI providers through a unified adapter (`openai_compat.py`). The `ProviderManager` handles failover and backoff, so things keep running if an API goes down.

### 🔍 Parser System (`parsers/`)
The `ParserRegistry` discovers tool parsers at import time. Each parser implements the `Parser` protocol, mapping raw tool output to structured data.

### 🛡️ Security Layer (Root Modules)
Siyarix includes some neat security features:
- **PermissionGate**: A review stage before running commands.
- **DLP Engine**: Tries to mask sensitive data patterns.
- **CredentialStore**: Secures API keys locally.
- **AuditLogger**: Keeps a log of actions.

### 🎨 Output & Reporting (`output/`, `report/`)
The `OutputEngine` supports multiple formats and themes, and the `ReportEngine` compiles assessments into Markdown or HTML.

!!! info "Implemented Features vs. Stubs"
    Siyarix is a growing project. While features like **MultiWaveExecution** and **BudgetChecking** are active, some features listed in `chat/stubs.py` are placeholders designed for future expansion as I continue building out the tool.

## 📏 Development Conventions

To keep the codebase manageable, I try to follow these standards:
- **Type Hints:** Encouraged on public APIs.
- **Async First:** `asyncio` is used extensively.
- **Structured Data:** Using Python `dataclasses` for representing findings.
- **Error Handling:** Use `SiyarixException` instead of bare `except:` blocks.
- **Logging:** Standard Python logging (`logging.getLogger(__name__)`).
- **Testing:** We rely on `pytest`. Let's try to keep coverage up!
- **Linting:** Using **Ruff** for formatting and linting.
