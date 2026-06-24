# 🏛️ Module Architecture

Curious how Siyarix ticks under the hood? This document breaks down the internal architecture of key Siyarix v1.0.0 modules, detailing how they interact, data flows, and the design patterns that power the platform.

## 🧩 Module Organization

Siyarix is neatly organized into top-level package directories and standalone modules. Here's your map:

| Module | Responsibility |
|--------|----------------|
| `core/` | 🧠 The orchestrator kernel: `AgentCore`, `SwarmRouter`, and `CommandPipeline`. |
| `chat/` | 💬 The interactive REPL: UI, session management, and the core LLM engine. |
| `providers/` | ☁️ The 24-provider LLM abstraction layer with failover and usage tracking. |
| `parsers/` | 🔍 80+ auto-discovering tool output parsers. |
| `plugins/` | 🔌 Dynamic plugin loader (loads from `~/.siyarix/plugins/`). |
| `output/` | 🎨 The rendering engine (8 formats, 12 themes). |
| `report/` | 📊 The security report generator (Markdown, HTML, SARIF, JSON). |
| `stealth.py` | 🥷 Stealth and evasion engine for covert ops. |
| `dlp.py` | 🛡️ Data Loss Prevention with bidirectional token masking. |
| `permission_gate.py`| 🚧 Two-stage command access control. |
| `credential_store.py`| 🔐 AES-256-GCM encrypted credential vault. |
| `workflow.py` | 🔄 DAG-based workflow engine. |

*(And 40+ additional specialized standalone modules!)*

## ⚙️ Execution Engine (`executor.py`, `executor_registry.py`, `executor_autonomous.py`)

The Execution Engine is the muscle of Siyarix. It operates in three distinct modes, dispatched by the Task Planner:

| Mode | Planner | Permission Level | Autonomy | Best For |
|------|---------|------------------|----------|----------|
| `REGISTRY` | RegistryPlanner (template) | Full gate | None | Offline, deterministic tasks. |
| `AUTONOMOUS`| AutonomousPlanner (LLM) | Minimal | Full | Unattended AI-driven operations. |
| `HYBRID` *(Default)*| Combined | Full gate | User confirmation | Interactive, guided security work. |

### 🌊 Execution Flow
1. The **Planner** generates an `ExecutionPlan` full of `ExecutionStep` objects.
2. Each step must pass through the **PermissionGate** (which returns ALLOW, DENY, or REVIEW).
3. Steps execute with high-performance parallelism using `asyncio.gather()`.
4. Output is seamlessly parsed via the **ParserRegistry**.
5. Structured findings are permanently ingested into the **KnowledgeGraph**.
6. Transient errors trigger automatic exponential backoffs via the **ProviderStateManager**.

> [!TIP]
> **Worker Pool Throttling:** Siyarix uses `asyncio.Semaphore` in `worker_pool.py` to bound concurrency. This prevents resource exhaustion when the agent tries to run 100 tools at once!

## 🗺️ Task Planners (`planner.py`, `planner_registry.py`, `planner_autonomous.py`)

Siyarix features a robust dual-planner architecture:

- **Registry Planner:** A deterministic, template-based planner that relies on keyword matching and intent classification. Zero AI dependency; it always works, even offline.
- **Autonomous Planner:** The LLM-driven genius. It translates natural language goals into structured execution plans. It natively supports self-repair if the initial tool call is malformed!
- **Planner Router:** Automatically dynamically routes between the two depending on user mode and cloud provider availability.

## 🚧 Permission Gate (`permission_gate.py`)

Security agents shouldn't nuke your hard drive. Before any command executes, Siyarix runs a rigid two-stage review:

1. **Syntax Gate:** Checks structural limits, shell injection attempts, and character restrictions.
2. **Danger Analysis:** Scans against 38+ dangerous categories (e.g., fork bombs, network floods, privilege escalation).

It will return `ALLOW`, `DENY` (with an explanation), or prompt the user for `REVIEW`.

## ☁️ Provider Manager (`providers/manager.py`)

Siyarix integrates an astonishing **24 AI providers** behind a single, unified `ProviderManager`:

- **Cloud (19 profiles):** OpenAI, Anthropic, Gemini, Groq, DeepSeek, and more.
- **Local (5 profiles):** Ollama, LM Studio, llama.cpp, vLLM. Zero API keys needed!
- **Fallback:** Offline heuristic registry.

> [!IMPORTANT]
> **The Failover Chain**
> If your primary provider goes down, Siyarix doesn't crash. It seamlessly fails over to your secondary cloud provider, then drops to Local LLMs, and ultimately falls back to the Offline Registry if all else fails.

## 🔐 Credential Store (`credential_store.py`)

Your API keys are precious. Siyarix guards them aggressively:
- **Encryption:** AES-256-GCM (32-byte key, 12-byte nonce).
- **Storage:** Handled safely via the OS system keyring.
- **Memory Safety:** Credentials are automatically scrubbed from memory when a session ends.
- Keys are **never** logged to the console or written to configuration files in plain text.

## 🛡️ DLP Engine (`dlp.py`)

Our **Data Loss Prevention** engine ensures you don't leak secrets to third-party LLM providers:
- Evaluates traffic against 40+ regex patterns (AWS keys, Passwords, SSH keys).
- **Bidirectional Masking:** It masks data before it goes to the cloud, and unmasks it when displaying responses back to you locally!

## 🧠 Knowledge Graph (`knowledge_graph.py`)

Siyarix builds an in-memory directed graph of everything it learns:
- **Nodes:** Hosts, ports, vulnerabilities, credentials.
- **Edges:** Relationships (e.g., `runs_on`, `has_vulnerability`).
- **Power:** Used heavily by the Report Engine for mapping evidence and providing rich context.

## 🐝 Swarm Architecture (`core/swarm.py`)

For complex campaigns, Siyarix deploys a Swarm of specialized sub-agents:
- **ReconAgent:** Maps the terrain and discovers assets.
- **ExploitAgent:** Safely validates discovered vulnerabilities.
- **ReportAgent:** Synthesizes the data into actionable intelligence.

The `SwarmRouter` coordinates task decomposition and smooth handoffs between these specialized phases.

## 📈 Learning System (`learning_system.py`)

Siyarix gets smarter over time. The **Learning System** continuously observes executions and builds a persistent, privacy-preserving skill library. 
It utilizes BM25-style Jaccard similarity and Bayesian confidence scoring—all implemented natively in standard Python without bulky Machine Learning frameworks!
