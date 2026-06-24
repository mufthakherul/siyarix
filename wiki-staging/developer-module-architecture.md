# 🏛️ Module Architecture

Curious how Siyarix ticks under the hood? This document breaks down the internal architecture, detailing how modules interact and the design patterns I used while building this personal passion project.

## 🧩 Module Organization

Siyarix is organized into directories and standalone modules. Here's a map:

| Module | Responsibility |
|--------|----------------|
| `core/` | 🧠 The orchestrator kernel: `AgentCore`, `SwarmRouter`, and `CommandPipeline`. |
| `chat/` | 💬 The interactive REPL UI, session management, and LLM engine. |
| `providers/` | ☁️ AI provider abstraction layer and API management. |
| `parsers/` | 🔍 Tool output parsers. |
| `plugins/` | 🔌 Dynamic plugin loader. |
| `output/` | 🎨 The rendering engine. |
| `report/` | 📊 Security report generation. |
| `stealth.py` | 🥷 Basic stealth configurations for tools. |
| `dlp.py` | 🛡️ Data masking helper. |
| `permission_gate.py`| 🚧 Command access control. |
| `credential_store.py`| 🔐 Local encrypted credential vault. |
| `workflow.py` | 🔄 Workflow execution logic. |

## ⚙️ Execution Engine

The Execution Engine operates in three modes, dispatched by the Task Planner:

| Mode | Planner | Permission Level | Autonomy |
|------|---------|------------------|----------|
| `REGISTRY` | Template-based | Full gate | None |
| `AUTONOMOUS`| LLM-driven | Minimal | Full |
| `HYBRID` *(Default)*| Combined | Full gate | User confirmation |

### 🌊 Execution Flow
1. The **Planner** generates an `ExecutionPlan`.
2. Each step passes through the **PermissionGate**.
3. Steps execute using `asyncio.gather()`.
4. Output is parsed via the **ParserRegistry**.
5. Transient errors are handled by the **ProviderStateManager**.

> [!TIP]
> **Worker Pool Throttling:** Siyarix uses `asyncio.Semaphore` to limit concurrency and prevent resource exhaustion.

## 🗺️ Task Planners

Siyarix uses a dual-planner architecture:
- **Registry Planner:** A deterministic, template-based planner using keyword matching. 
- **Autonomous Planner:** The LLM-driven planner that translates natural language into execution steps.

## 🚧 Permission Gate (`permission_gate.py`)

To help prevent accidents, Siyarix runs a review before execution:
1. **Syntax Gate:** Checks structural limits.
2. **Danger Analysis:** Scans against potentially dangerous commands.
It returns `ALLOW`, `DENY`, or asks the user for `REVIEW`.

## ☁️ Provider Manager (`providers/manager.py`)

The `ProviderManager` handles integrations with various AI providers (OpenAI, Anthropic, Gemini, Ollama, etc.). It includes failover logic so you can keep working if your primary provider goes down.

## 🔐 Credential Store (`credential_store.py`)

To keep your API keys safer, the `CredentialStore` encrypts them locally using AES-256-GCM and the OS system keyring, avoiding plaintext configuration files.

## 🛡️ DLP Engine (`dlp.py`)

The DLP engine is a lightweight tool to help prevent accidentally leaking secrets (like AWS keys or local passwords) to cloud providers by masking them before sending prompts.

## 🧠 Knowledge Graph (`knowledge_graph.py`)

An in-memory directed graph of discovered nodes (Hosts, ports, vulnerabilities) that helps provide context for the report engine.

## 🐝 Swarm Architecture (`core/swarm.py`)

A simple multi-agent setup where tasks are broken down between specialized sub-agents (Recon, Exploit, Report).

## 📈 Learning System (`learning_system.py`)

A privacy-preserving feature that tries to remember past successful executions and command structures to improve future runs locally, without relying on external ML frameworks.
