# Siyarix Security Agent — Comprehensive Master Documentation

> **Project:** github.com/mufthakherul/siyarix  
> **Classification:** Cybersecurity-Native AI Agent & Universal Tool Orchestrator  
> **Maintainer:** mufthakherul & Contributing Team  
> **License:** MIT+custom sensors as this is a sencetive  
> **Status:** Active Development — Community-Driven Discovery Encouraged  
> **Document Version:** Edition v2.0 — Enhanced with Suggested Roadmap  

---

## Migration Execution Plan (Working)

This section is maintained by the automated migration effort driven by the engineering agent.
It records progress, decisions, blockers and a succinct roadmap so reviewers can follow changes.

- **Overall Goal:** Migrate repository to enterprise-grade architecture, modernize patterns, improve security, observability, performance and extensibility while preserving backward compatibility where practical.
- **Owner:** Automated migration agent (working with maintainers)
- **Status (global):** 20% — Phase 1 adaptive foundation actively implemented

Progress by Part:

- **Part I (Core Architecture & Features):** 28%
- **Part II (Advanced Operational Workflows):** 8%
- **Part III (Suggested Enhancements & Roadmap):** 5%
- **Part IV (Enterprise & Team Scaling):** 6%
- **Part V (Integration Ecosystem):** 2%
- **Part VI (Security Hardening & Compliance):** 12%

Initial actions taken:

1. Performed repository graph analysis (graphify-out) and loaded `migration.md` to construct an actionable migration roadmap.
2. Created this execution plan area and a companion `MIGRATION_PLAN.md` (root) with prioritized tasks and phases.
3. Next: begin targeted, incremental changes starting with static analysis, typing, and CI test stability to create a safe baseline for larger refactors.

Changelog (automated agent):

- 2026-05-24: Phase 1 feedback-loop + multi-agent wiring
  - Fixed provider subsystem merge regression by consolidating `src/siyarix/providers.py` into a single compatible registry/protocol implementation.
  - Fixed `src/siyarix/tool_executor.py` import/runtime defects (`ResolveResult` import mismatch and shell-step duration calculation).
  - Fixed `ExecutionEngine` initialization ordering in `src/siyarix/engine.py` (resolver/graph created before `ToolExecutor`), and unified runtime step types by removing duplicated local `StepStatus`/`StepResult` definitions.
  - Added XI runtime integration in `ExecutionEngine` context building and step feedback tracking (`ContextTracker` + `Predictor`).
  - Added adaptive re-plan trigger path: failed/zero-finding step outcomes now feed back into planner (`TaskPlanner.replan`) and can inject corrective next steps dynamically.
  - Added coordinator wiring for multi-agent objective dispatch in `src/siyarix/agents/coordinator.py` and `ExecutionEngine.execute_objective(...)`, connecting `AgentTeam` with `SOCAgent` and `DFIRAgent`.
  - Added tests:
    - `tests/test_adaptive_replan.py`
    - `tests/test_multi_agent_coordinator.py`
  - Compatibility notes:
    - Existing `NoopProvider` behavior remains backward compatible for both lightweight and registry-instantiated usage patterns.
    - Adaptive re-plan is bounded by `max_replans` (default: 3) to avoid runaway loops.
  - Status (global): ~20% — Phase 1 feedback/adaptation architecture and coordinator integration in place.

- 2026-05-24: Discovery complete. Actions performed by migration agent:
  - Added `Migration Execution Plan` and progress tracker section (this file).
  - Created `MIGRATION_PLAN.md` with phased roadmap and immediate next steps.
  - Added `tool.mypy` configuration to `pyproject.toml` to enable type checks in CI.
  - Introduced lightweight structured logging helper at `src/siyarix/logging_config.py`.
  - Initialized centralized logging in `src/siyarix/main.py` using configured `log_level`.
  - Created CI improvements note; existing CI workflow detected and will be leveraged.
  - Status (global): ~2% — Baseline hardening started (static config + logging).
  
- 2026-05-24: Masking engine
  - Added session-scoped masking engine at `src/siyarix/masking.py` implementing deterministic mask/unmask and exportable mapping.
  - Added unit tests at `tests/test_masking.py` covering domain and API key masking and reset behavior.
  - Status (global): ~3% — Safety primitives in place.

- 2026-05-24: Provider abstraction
  - Added `src/siyarix/providers.py` with `Provider` protocol, `ProviderRegistry`, and `NoopProvider` fallback.
  - Updated `src/siyarix/engine.py` to register providers through `ProviderRegistry` and add `NoopProvider` as a safe fallback.
  - Added unit tests at `tests/test_providers.py`.
  - Status (global): ~6% — Provider seam introduced and engine wired to registry.

- 2026-05-24: Engine provider integration
  - Added `tests/test_engine_providers.py` to validate ExecutionEngine provider registration.
  - Status (global): ~7% — Engine validates provider wiring in unit tests (CI will verify).

- 2026-05-24: Worker pool
  - Added bounded async worker pool at `src/siyarix/worker_pool.py` (already present) and unit tests at `tests/test_worker_pool.py`.
  - Status (global): ~8% — Concurrency primitives tested and integrated into ExecutionEngine.

- 2026-05-24: Response sensor & redaction
  - Added `src/siyarix/response_sensor.py` to centralize masking/unmasking and redaction for model interactions.
  - Integrated `ResponseSensor` into `src/siyarix/planner.py` model call flow with fallback to legacy masking.
  - Added unit tests at `tests/test_response_sensor.py`.
  - Status (global): ~9% — Sensitive data handling centralized; planner uses redaction before exposing outputs.

- 2026-05-24: Provider adapters
  - Added `src/siyarix/provider_adapters.py` which wraps existing planner model classes into the `Provider` ABC and registers adapters (`openai`, `gemini`, `ollama`, `cloud`) with the provider registry.
  - Status (global): ~10% — Model providers unified behind a single registry-driven interface.

- 2026-05-24: CI workflow
  - Added GitHub Actions CI workflow at `.github/workflows/ci.yml` to run tests on push and PRs.
  - Status (global): ~11% — Automated test runs configured; CI will validate environment-sensitive tests.

- 2026-05-24: Engine registry integration
  - Updated `src/siyarix/engine.py` to instantiate model provider adapters from the central `providers.registry` (adapters live in `src/siyarix/provider_adapters.py`).
  - Engines now respect `model_provider` preference and attach availability flags to adapters when possible.
  - Status (global): ~12% — Engine uses registry-driven provider adapters for unified provider handling.

- 2026-05-24: ToolExecutor extraction
  - Extracted execution responsibilities into `src/siyarix/tool_executor.py` and centralised step execution there. Introduced `src/siyarix/engine_types.py` for shared `StepResult`/`StepStatus` types.
  - Updated `src/siyarix/engine.py` to delegate step execution to `ToolExecutor` and added unit test at `tests/test_tool_executor.py`.
  - Status (global): ~14% — Execution logic separated, enabling DI and easier unit testing.

- 2026-05-24: Findings parsing & ingestion
  - Enhanced `ToolExecutor` to parse tool outputs with existing parsers and ingest findings into the `KnowledgeGraph`. Notifications are emitted per finding and metrics updated.
  - Status (global): ~15% — Tool outputs now produce structured findings in the knowledge graph.

- 2026-05-24: Parser tests
  - Added unit tests for key parsers: `tests/test_parsers_gobuster.py`, `tests/test_parsers_nmap.py`.
  - Status (global): ~16% — Parser coverage increased for core tools.

- 2026-05-24: Provider abstraction
  - Added provider interface and registry at `src/siyarix/providers.py`.
  - Added `NoopProvider` scaffold and registered it as `noop` for offline/testing.
  - Added unit tests at `tests/test_providers.py`.
  - Status (global): ~4% — LLM provider seam established.
  
- 2026-05-24: Provider async update
  - Updated provider interface to use async methods to match planner expectations.
  - Updated `NoopProvider` and tests to use async flows.
  - Status (global): ~4.5% — Provider seam compatible with planner protocol.

- 2026-05-24: Planner masking integration
  - Integrated `MaskingEngine` into `TaskPlanner._plan_from_model` to mask instructions and serialized context before sending to model providers.
  - Model responses are recursively unmasked before parsing to ExecutionPlan.
  - Status (global): ~5% — OPSEC masking integrated into planning path.

- 2026-05-24: Async worker pool
  - Added `AsyncWorkerPool` at `src/siyarix/worker_pool.py` to provide bounded concurrency for sub-agents.
  - Added unit tests at `tests/test_worker_pool.py`.
  - Status (global): ~6% — Execution concurrency primitives added.


Change policy and traceability:

- Every substantive change will include a changelog entry in `migration.md` (this section) with: date, files modified, rationale, tests added/updated, and compatibility notes.
- Backwards-incompatible changes will be gated behind feature flags and documented migration adapters.

---

## Document Structure

* **Part I:** Core Architecture & Features 
* **Part II:** Advanced Operational Workflows 
* **Part III:** Suggested Enhancements & Roadmap 
* **Part IV:** Enterprise & Team Scaling 
* **Part V:** Integration Ecosystem 
* **Part VI:** Security Hardening & Compliance 

---

# PART I: CORE ARCHITECTURE & FEATURES

---

## Chapter 1: System Architecture Deep Dive

### 1.1 The Seven-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 7: USER INTERFACE & INTERACTION                                       │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────────┐       │
│ │   CLI Mode   │ │ Interactive  │ │   Chat Mode  │ │   VS Code      │       │
│ │   (Direct)   │ │    Shell     │ │   (REPL)     │ │ (/coder_sec)   │       │
│ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬─────────┘       │
│        └────────────────┴────────────────┴────────────────┘                 │
│                              │                                              │
│ LAYER 6: SIYARIX CORE ENGINE │                                              │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐   │ │ 
│ │  │   Persona    │  │   Planner    │  │     Execution Engine         │   │ │
│ │  │   Engine     │  │  (AI/Local)  │  │     (15+ Sub-Agent Pool)     │   │ │
│ │  │              │  │              │  │                              │   │ │
│ │  │ • Work-Mode  │  │ • Natural    │  │ • Parallel Task Execution    │   │ │
│ │  │ • Custom     │  │   Language   │  │ • Cross-Platform Shell       │   │ │
│ │  │ • Auto-Mode  │  │   Parser     │  │ • Tool Discovery             │   │ │
│ │  │ • None-Mode  │  │ • Intent     │  │ • Permission Gates           │   │ │
│ │  │              │  │   Router     │  │ • ESC Interception           │   │ │
│ │  └──────────────┘  └──────────────┘  └──────────────────────────────┘   │ │
│ │                              │                                          │ │
│ │  ┌───────────────────────────────────────────────────────────────────┐  │ │
│ │  │              SAFETY & SANITIZATION LAYER                          │  │ │
│ │  │  ┌────────────┐  ┌─────────────┐  ┌──────────────────────────┐    │  │ │
│ │  │  │   Prompt   │  │  Response   │  │ Command Sandbox+masking  │    │  │ │
│ │  │  │   Sensor   │  │   Sensor    │  │                          │    │  │ │
│ │  │  │            │  │             │  │ • real target Masking    │    │  │ │
│ │  │  │ • Mask IPs │  │ • Detect    │  │ • IP Masking             │    │  │ │
│ │  │  │ • Mask     │  │   Forbidden │  │ • Token Masking          │    │  │ │
│ │  │  │   Domains  │  │   Commands  │  │ • Regex Patterns         │    │  │ │
│ │  │  │ • Mask API │  │ • Detect    │  │ • Whitelist/Blacklist    │    │  │ │
│ │  │  │   Keys     │  │   Permission│  │ • Auto-Approve Config    │    │  │ │
│ │  │  │ • Custom   │  │ • Unmask    │  │ • ESC Kill Switch        │    │  │ │
│ │  │  │   Regex    │  │   for Exec  │  │ • Shell Review Loop      │    │  │ │
│ │  │  └────────────┘  └─────────────┘  └──────────────────────────┘    │  │ │
│ │  └───────────────────────────────────────────────────────────────────┘  │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                              │                                              │
│ LAYER 5: INTEGRATION & EXTENSION                                            │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │
│ │   Plugin     │ │     MCP      │ │   Collab     │ │    Coder     │         │
│ │   System     │ │   Servers    │ │   (SSH)      │ │    (VS)      │         │
│ │  (/plugin)   │ │  (Research)  │ │  (/collab)   │ │  (/coder)    │         │
│ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘         │
│        └────────────────┴────────────────┴────────────────┘                 │
│                              │                                              │
│ LAYER 4: KNOWLEDGE & MEMORY                                                 │
│ ┌───────────────┐ ┌──────────────┐ ┌────────────────────────────────────┐   │
│ │   Advance     │ │   Learning   │ │         Session Logs               │   │
│ │ Tool Registry │ │   Memory     │ │      (/log <session-id>)           │   │
│ │  (LLM-Free)   │ │ (User/Tool)  │ │                                    │   │
│ └───────────────┘ └──────────────┘ └────────────────────────────────────┘   │
│                              │                                              │
│ LAYER 3: AI PROVIDER PLUGGABLE BACKBONE                                     │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐       │
│ │  OpenAI  │ │  Gemini  │ │  Ollama  │ │  Custom  │ │   Local LLM   │       │
│ │  (GPT)   │ │ (Google) │ │ (Local)  │ │ Endpoint │ │  (GPU/CPU)    │       │
│ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───────┬───────┘       │
│      └────────────┴────────────┴────────────┴───────────────┘               │
│                              │                                              │
│ LAYER 2: BIDIRECTIONAL DATA MASKING (Privacy Shield)                        │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │    REAL DATA (xyz.com, 192.168.1.1, sk-...)                             │ │
│ │         ↕                                                               │ │
│ │    MASKED DATA (example.com, 10.0.0.1, [REDACTED])                      │ │
│ │         ↕                                                               │ │
│ │    LLM API (Cloud Provider — Never Sees Real Targets)                   │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                              │                                              │
│ LAYER 1: TARGET ENVIRONMENT ADAPTATION                                      │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐   │
│ │  Kali    │ │  macOS   │ │ Windows  │ │ Harmony  │ │   Cloud Shell     │   │
│ │  Linux   │ │  (Zsh)   │ │(PS/CMD/  │ │   OS     │ │ (Codespaces/      │   │
│ │          │ │          │ │  WSL)    │ │          │ │  CloudShell)      │   │
│ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────────┬─────────┘   │
│      └────────────┴────────────┴────────────┴─────────────────┘             │
│                              │                                              │
│         INSTALLED TOOLS POOL (Auto-Discovered via PATH Scan + ACL)          │
│         nmap │ nuclei │ ffuf │ metasploit │ burpsuite │ custom scripts      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Interaction Flow

```
User Input
    │
    ▼
┌─────────────────┐
│ Persona Engine  │ ──→ Selects context (offensive/defensive/bug hunter/etc.)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Prompt Sensor   │ ──→ Masks sensitive data (...target, domains, IPs, tokens, credentials)
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────────────┐
│   AI Planner    │ or  │  Advanced Tool Registry  │ ──→ If no LLM connected
│   (LLM Mode)    │     │      (Direct Mode)       │
└────────┬────────┘     └──────────────────────────┘
         │
         ▼
┌─────────────────┐
│ Response Sensor │ ──→ Detects forbidden commands, permission requirements
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Unmasking     │ ──→ Restores real targets from dummy placeholders
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Execution     │ ──→ Spawns sub-agents, platform-adapted shell commands
│    Engine       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Output Capture  │ ──→ Real-time stdout/stderr streaming
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Learning Memory │ ──→ Stores patterns (if tool mode on)
│   + Logging     │ ──→ Saves session audit (always)
│   + Learning    │ ──→ Learn from user modifications (if self learning mode on)
│   + Teaching    │ ──→ Explains to user (if user learning mode on)
└─────────────────┘
```

---

## Chapter 2: Installation & Bootstrap System

### 2.1 Installation Methods

| Method | Command | Use Case |
|--------|---------|----------|
| PyPI (Stable) | `pip install siyarix` | End users, quick start |
| Source (Dev) | `git clone ... && pip install .` | Contributors, latest features |
| Container | `docker pull siyarix` *(suggested)* | Isolated environments |
| Package Manager | `apt install siyarix` *(suggested)* | System-wide Linux installs |

### 2.2 The Bootstrap Process (First-Run Magic)

**Trigger:** Running `siyarix` for the first time (no config marker found).

**Detailed Sequence:**

| Phase | Action | Platform Detection |
|-------|--------|-------------------|
| **T1** | Check first-run marker (`~/.siyarix/.initialized` or registry key) | Universal |
| **T2** | Detect OS: Linux/macOS/Windows/HarmonyOS/Cloud | `platform.system()` + environment variables |
| **T3** | Detect terminal: Bash/Zsh/Fish/CMD/PowerShell/WSL | `SHELL` env var + `ps` detection |
| **T4** | Execute bootstrap script to install all necessary applicactions, packages, and other to run siyarix: `.sh` / `.bat` / `.ps1` | Platform-matched extension |
| **T5** | Check Python ≥3.11 | `sys.version_info` |
| **T6** | Verify pip dependencies from `requirements.txt` | `pkg_resources` or `importlib.metadata` |
| **T7** | Check database backend  | Connection test + schema initialization |
| **T8** | Verify runtime dependencies  | PATH scan for auxiliary compilers |
| **T9** | Prompt for missing dependency installation | Interactive Y/n per package |
| **T10** | Auto-install approved packages | `subprocess.run([pip, install, ...])` |
| **T11** | Write first-run marker | `~/.siyarix/.initialized` |
| **T12** | Display completion message | *"All done! Please restart your terminal."* |

**Second Run Behavior:**
- Reads first-run marker → skips bootstrap entirely 
- Loads `~/.siyarix/config.yaml` (or equivalent)
- Initializes main engine directly
- Scans PATH for tools
- Displays tool inventory
- Prompts for LLM setup if not configured

### 2.3 Lazy Module Loading Architecture

```python
# Conceptual architecture
class ProviderManager:
    def __init__(self):
        self.loaded_providers = {}
        self.available_providers = {
            'openai': 'siyarix-openai',
            'gemini': 'siyarix-gemini',
            'ollama': 'siyarix-ollama',
            'groq': 'siyarix-groq',
            'together': 'siyarix-together',
        }

    def load_provider(self, name):
        if name not in self.loaded_providers:
            package = self.available_providers.get(name)
            if not self._is_installed(package):
                self._prompt_install(package)
            self.loaded_providers[name] = self._import_module(package)
        return self.loaded_providers[name]
```

**Benefits:**
- No bloat from unused AI backends
- Community can add providers without core changes

---

## Chapter 3: Interactive Modes & User Experience

### 3.1 Mode Comparison Matrix

### 3.2 Hybride Interactive with Chat Mode (Default)

**Launch:** `siyarix` (no arguments)

**UI Features:**
- Syntax-highlighted output (if terminal supports it)
- Progress indicators for long-running sub-agents
- Tab completion for slash commands
- Command history (up/down arrows)
- eg. `/theme` — visual preference

**Input Handling:**
- Natural language → AI planner or Advanced Tool Registry
- Slash commands → Direct system control
- Raw tool syntax → Passthrough to execution engine (with safety checks)

### 3.3 Direct CLI Mode

**Quick Tasks:**
```bash
# Network scan
siyarix scan 192.168.1.1

# Natural language task
siyarix run "find subdomains of example.com"

# Tool registry direct
siyarix tool-registry run nmap -sV target.com
```

**Exit Codes:**
- `0`: Success
- `1`: Execution error
- `2`: Permission denied (user rejected)
- `3`: Tool not found
- `4`: LLM error / timeout

---

## Chapter 4: The Persona Engine ('/Work-Mode' System)

### 4.1 Built-in Personas (some example on table but you need add more )

| Persona | System Prompt Focus | Tool Filter | Workflow Template | Learning Bias |
|---------|---------------------|-------------|-------------------|---------------|
| **Offensive** | *"You are an offensive security operator..."* | All attack tools enabled | Recon → Exploitation → Post-Exploitation → Reporting | Aggressive chaining |
| **Defensive** | *"You are a defensive security analyst..."* | Monitoring/hardening tools | Detect → Triage → Contain → Remediate | Cautious validation |
| **Bug Hunter** | *"You are a bug bounty hunter..."* | Web/app tools prioritized | Scope Validation → Recon → Testing → PoC → Report | Methodical documentation |
| **Pentester** | *"You are a penetration tester..."* | Full toolkit | Planning → Execution → Evidence → Reporting | Compliance-aware |
| **SOC Analyst** | *"You are a SOC analyst..."* | SIEM/EDR/forensics | Alert → Investigate → Escalate → Resolve | Time-sensitive |
| **None** | *"You are a universal security agent..."* | No restrictions | Context-dependent | Balanced |
| **Auto** | *Dynamic selection* | Best-fit per prompt | Intent-classified | Adaptive |

### 4.2 Auto Mode Deep Dive

**Intent Classification Pipeline:**

```
User Prompt: "Check if this server is vulnerable to Log4j"
    │
    ▼
┌─────────────────────┐
│ Intent Classifier   │ ──→ Keywords: "vulnerable", "Log4j", "server"
│ (Local / LLM-based) │ ──→ Domain: Vulnerability Assessment
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Persona Selector    │ ──→ Match: Bug Hunter (vuln-focused)
│ (Confidence Score)  │ ──→ Score: 0.87 (high confidence)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Context Loader      │ ──→ Load bug hunter system prompt
│                     │ ──→ Filter tool registry to vuln scanners
│                     │ ──→ Load CVE-focused workflow template
└─────────────────────┘
```

**Performance Note:** Auto mode is little slower because it adds classification overhead. For repeated similar tasks, manual `/work-mode` is recommended.

### 4.3 Custom Persona Creation (Verified)

```
siyarix> /work-mode custom

[Persona Builder]
Name: cloud-pentester
Description: AWS/Azure/GCP security assessment specialist
System Prompt: You specialize in cloud misconfigurations and privilege escalation...

Tool ACL:
  Allowed: prowler, scoutsuite, pacu, cloudsplaining, awscli
  Forbidden: metasploit, nmap (network-level)
  Permission: iam-policy-modification, role-assumption

Workflow Template:
  1. CSPM scan (Prowler)
  2. IAM analysis (CloudSplaining)
  3. Privilege escalation paths (Pacu)
  4. Report generation

Auto-approve: 15s
Safety profile: cautious
```

**Custom Persona Storage:**
- Saved to `~/.siyarix/personas/<name>.yaml`
- Shareable between team members
- Can inherit from built-in personas

### 4.4 Persona Context Retargeting

When switching personas mid-session, Siyarix **hot-swaps**:

| Component | What Changes | Latency |
|-----------|-------------|---------|
| System Prompt | Injected into LLM context window | ~50ms |
| Tool Registry Filter | ACL re-evaluation | ~100ms |
| Workflow Template | Pre-loaded step sequences | ~20ms |
| Learning Memory | Persona-specific memory segment | ~30ms |
| Command Syntax | OS/terminal adaptations | ~10ms |

**Total context switch:** ~200ms — imperceptible to users.

---

## Chapter 5: AI Provider System

### 5.1 Provider Architecture

```
┌───────────────────────────────────────┐
│         Provider Interface            │
│  ┌─────────────────────────────────┐  │ 
│  │  connect(endpoint, key, model)  │  │
│  │  plan(prompt, context)          │  │
│  │  chat(history)                  │  │
│  │  validate()                     │  │
│  └─────────────────────────────────┘  │
└──────────────────┬────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌────────┐   ┌────────┐   ┌────────┐
│ OpenAI │   │ Gemini │   │ Ollama │
│Adapter │   │Adapter │   │Adapter │
└────────┘   └────────┘   └────────┘
```

### 5.2 Verified Provider Support

| Provider | Endpoint Format | Model Examples | Local/Cloud |
|----------|----------------|----------------|-------------|
| OpenAI | `https://api.openai.com/v1` | gpt-4-turbo, gpt-3.5-turbo, etc. others | Cloud |
| Gemini | `https://generativelanguage.googleapis.com` | gemini-1.5-pro, gemini-1.5-flash, etc. others | Cloud |
| Ollama | `http://localhost:11434` | llama3, mistral, codellama, etc. others | Local |
| LM Studio | `http://localhost:1234/v1` | Any loaded model, etc. others | Local |
| Groq | `https://api.groq.com/openai/v1` | llama3-70b, mixtral-8x7b, etc. others | Cloud (fast) |
| Together | `https://api.together.xyz/v1` | Various open models, etc. others | Cloud |
| Custom | User-defined AI-compatible | Any | Either |

### 5.3 Custom Provider Configuration

```
siyarix> /key set custom https://my-llm.company.com/v1 sk-abc123 my-model-v1

[Siyarix] Custom provider configured.
[Siyarix] Testing connection...
[Siyarix] Custom provider ready. Model: my-model-v1
```

**Use Cases for Custom Providers:**
- Internal company LLM (air-gapped)
- Self-hosted vLLM instance
- SecGPT or other security-tuned models
- Academic research endpoints

### 5.4 Secure Credential Vault

**Encryption:**
- AES-256-GCM for API keys at rest
- OS keyring integration (macOS Keychain, Windows DPAPI, Linux Secret Service)
- Keys decrypted only at runtime, only in memory

**Transmission:**
- HTTPS/TLS 1.3 to provider endpoints
- Keys never logged, never displayed in output
- No proxying through Siyarix servers (direct to provider)

**Rotation:**
```
siyarix> /key rotate openai
[Siyarix] Old key invalidated. Enter new key: sk-...
[Siyarix] Key updated. Testing...
[Siyarix] Rotation complete.
```

---

## Chapter 6: Tool Discovery & Orchestration

### 6.1 PATH Scanning Algorithm

```python
# Conceptual implementation
def discover_tools():
    discovered = {}
    for directory in os.environ['PATH'].split(os.pathsep):
        for executable in os.listdir(directory):
            if is_security_tool(executable):  # Signature matching
                version = get_version(executable)
                capabilities = infer_capabilities(executable)
                discovered[executable] = {
                    'version': version,
                    'path': os.path.join(directory, executable),
                    'capabilities': capabilities,
                    'category': categorize(executable)
                }
    return discovered
```

**Signature Matching:**
- Known tool names (nmap, nuclei, ffuf, etc.)
- Binary analysis for custom tools
- Metadata extraction (help flags, version strings)
- Community-contributed signatures via plugin system

### 6.2 Tool Categories (Auto-Detected)

| Category | Examples | Typical Use |
|----------|----------|-------------|
| Reconnaissance | nmap, subfinder, amass, dnsx | Network mapping |
| Web Scanning | nuclei, ffuf, dirsearch, gobuster | Web app testing |
| Exploitation | metasploit, sqlmap, xsser | Vulnerability exploitation |
| Post-Exploitation | bloodhound, mimikatz, impacket | Privilege escalation |
| Forensics | volatility, sleuthkit, autopsy | Incident response |
| Cryptography | hashcat, john, openssl | Password cracking, crypto analysis |
| Social Engineering | gophish, setoolkit | Phishing simulation |
| Wireless | aircrack-ng, wifite | WiFi security |
| Mobile | apktool, jadx, objection | Mobile app testing |
| Cloud | prowler, scoutsuite, pacu | Cloud security |
| Containers | trivy, docker-bench, kube-bench | Container security |
| Custom | User-installed scripts | Specialized workflows |

### 6.3 Tool Access Control (ACL) Deep Dive

**Permission Levels:**

| Level | Code | Behavior | Example |
|-------|------|----------|---------|
| **Enabled** | `ON` | AI can plan with it; direct execution allowed | `nmap`, `curl` |
| **Disabled** | `OFF` | Hidden from AI; manual enable required | `metasploit` (in bug hunter mode) |
| **Forbidden** | `FORBIDDEN` | Never executable; blocked at sensor layer | `rm -rf /`, `mkfs` |
| **Permission** | `PERMISSION` | Requires explicit user approval per execution | `sudo`, `msfvenom` |
| **Review** | `REVIEW` | Generates script for user review before execution | Complex multi-step chains |

**Configuration Interface:**
```
siyarix> /config tool access

Global Settings:
  Auto-approve timeout: 10s → [Change]
  Default new tools: ON → [Change]

Per-Tool Control:
  nmap              [ON]        [↓] [FORBIDDEN] [PERMISSION]
  nuclei            [ON]        [↓] [FORBIDDEN] [PERMISSION]
  metasploit        [OFF]       [↑] [FORBIDDEN] [PERMISSION]
  rm                [FORBIDDEN] [↑] [OFF]       [PERMISSION]
  sudo              [PERMISSION] [↑] [OFF]         [FORBIDDEN]

[Save] [Reset to Defaults] [Import Profile] [Export Profile]
```

### 6.4 Missing Tool Auto-Installation

**Detection Flow:**

```
AI Plan: "Use nuclei to scan for CVEs"
    │
    ▼
[Execution Engine] Check PATH for "nuclei"
    │
    ▼
Not Found
    │
    ▼
[Siyarix] "nuclei required but not found."
[Siyarix] "Install nuclei? [Y/n/a(always)/N(never)]: Y"
    │
    ▼
Platform Detection → Select Install Method:
    • Linux: `apt install nuclei` or `go install`
    • macOS: `brew install nuclei`
    • Windows: `choco install nuclei` or manual
    │
    ▼
[Siyarix] Installing...
[Siyarix] nuclei v3.1.0 installed successfully.
[Siyarix] Resuming task...
```

**Install Methods (Platform-Matched):**
- Package managers: `apt`, `brew`, `choco`, `pacman`, `dnf`
- Language-specific: `pip`, `gem`, `npm`, `go install`
- Binary downloads: GitHub releases, official binaries
- Source compilation: `git clone && make` (fallback)

---

## Chapter 7: Safety & Privacy Architecture

### 7.1 Bidirectional Data Masking System

**The Problem:** Sending real target names to cloud LLMs leaks operational security (OPSEC) information.

**Siyarix Solution:**

```
┌──────────────────────────────────────────────────────────────┐
│                    MASKING ENGINE                            │
│                                                              │
│  Input:  "Scan xyz.com for vulnerabilities"                  │
│                                                              │
│  Pattern Registry:                                           │
│    • Domain Regex:  (?<domain>[a-z0-9-]+\.[a-z]{2,})         │
│    • IP Regex:      (?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})│
│    • API Key:       (?<apikey>sk-[a-zA-Z0-9]{48})            │
│    • Token:         (?<token>eyJ[a-zA-Z0-9_-]*\.eyJ)         │
│    • Custom:        User-defined regex patterns              │
│                                                              │
│  Masking Map (Session-Scoped):                               │
│    xyz.com        →  example.com                             │
│    192.168.1.1    →  10.0.0.1                                │
│    sk-live-abc...  →  [REDACTED]                             │
│                                                              │
│  Masked Prompt:  "Scan example.com for vulnerabilities"      │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   LLM API Call  │
                    │ (Cloud Provider)│
                    │  Never sees real│
                    │     targets     │
                    └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   UNMASKING ENGINE                            │
│                                                             │
│  LLM Response: "Use nmap -sV example.com"                  │
│                                                             │
│  Reverse Map:                                               │
│    example.com  →  xyz.com                                  │
│                                                             │
│  Unmasked Command: "Use nmap -sV xyz.com"                  │
└─────────────────────────────────────────────────────────────┘
```

**Custom Masking Rules:**
```
siyarix> /config masking add

Pattern name: internal-domain
Regex: int\.company\.local
Replacement: internal.example.local
Scope: all          # all / offensive-only / defensive-only

[Siyarix] Masking rule added. 47 patterns active.
```

### 7.2 Response Sensor & Permission Gates

**Three-Stage Filtering:**

```
LLM Response (with masked data)
    │
    ▼
┌─────────────────────────┐
│ Stage 1: Syntax Check   │ ──→ Valid command structure?
│                         │ ──→ No shell injection patterns?
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Stage 2: Forbidden Check│ ──→ Match against forbidden list?
│                         │ ──→ Match against system blacklist?
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Stage 3: Permission     │ ──→ Match against permission-required list?
│         Check           │ ──→ User approval required?
└──────────┬──────────────┘
           │
           ▼
    [ALLOWED] → Unmask → Execute
    [FORBIDDEN] → Block → Alert → [PERMISSION]
    [PERMISSION] → Prompt → Wait → Unmask → Execute (if approved)
```

### 7.3 Shell Injection Review Loop

**For complex multi-step operations:**

```bash
[Siyarix] Generated execution plan (5 steps):

#!/bin/bash
# Step 1: Reconnaissance
subfinder -d xyz.com -o subs.txt

# Step 2: Live host check
cat subs.txt | httpx -o live.txt

# Step 3: Technology detection
nuclei -l live.txt -t technologies/

# Step 4: Vulnerability scan
nuclei -l live.txt -t cves/ -severity critical,high

# Step 5: Report
cat *.txt | tee report.md

[Review Options]:
  [E]dit in $EDITOR
  [R]un as-is
  [S]tep through (confirm each step)
  [C]ancel

Choice: E
[User edits in VS Code / nano / vim...]
[Siyarix] Detected modifications. Diff:
  - nuclei -l live.txt -t cves/ -severity critical,high
  + nuclei -l live.txt -t cves/ -severity critical,high,medium

[Execute modified script? Y/n]: Y
```

### 7.4 ESC Kill Switch

**Behavior:**
- Press `ESC` at any time during execution
- Sends SIGTERM to active sub-agent process
- Immediately returns control to interactive prompt
- Logs interruption with timestamp
- Partial results from other sub-agents preserved

**Scope:**
- Kills current command chain only
- Does not exit Siyarix session
- Does not affect other running `/collab` sessions

---

## Chapter 8: Multi-Agent Execution Engine

### 8.1 Sub-Agent Pool Architecture

```
┌───────────────────────────────────────────┐
│           Main Controller                 │
│  ┌─────────────────────────────────────┐  │
│  │         Task Queue                  │  │
│  │  [Task 1] [Task 2] [Task 3] ...     │  │
│  └─────────────────────────────────────┘  │
│                    │                      │
│    ┌───────────────┼───────────────┐      │
│    ▼               ▼               ▼      │
│ ┌──────┐      ┌──────┐      ┌──────┐      │
│ │Agent │      │Agent │      │Agent │      │
│ │  01  │      │  02  │      │  03  │      │
│ │DNS   │      │Port  │      │Web   │      │
│ │Enum  │      │Scan  │      │Probe │      │
│ └──────┘      └──────┘      └──────┘      │
│    │               │               │      │
│    └───────────────┼───────────────┘      │
│                    │                      │
│              ┌─────▼─────┐                │
│              │  Result   │                │
│              │ Aggregator│                │
│              └───────────┘                │
└───────────────────────────────────────────┘
```

**Pool Size:** Up to 15 concurrent sub-agents (configurable based on system resources).

**Agent Lifecycle:**
1. Spawned from pool
2. Assigned task + environment context
3. Executes in isolated subprocess
4. Streams stdout/stderr to aggregator
5. Returns exit code + output summary
6. Log agent works
7. Pool recycles or destroys agent

### 8.2 Cross-Platform Shell Translation

**Detection & Mapping:**

| Detected Environment | Shell | Command Translation Example |
|---------------------|-------|---------------------------|
| Linux (Bash) | `/bin/bash` | `ping -c 4 target` |
| Linux (Zsh) | `/bin/zsh` | `ping -c 4 target` |
| macOS (Zsh) | `/bin/zsh` | `ping -c 4 target` (macOS ping) |
| Windows (CMD) | `cmd.exe` | `ping -n 4 target` |
| Windows (PowerShell) | `powershell.exe` | `Test-NetConnection -ComputerName target` |
| Windows (WSL) | `wsl.exe` | `wsl ping -c 4 target` |
| HarmonyOS | Terminal app | Mobile-adapted commands |
| Cloud (Codespaces) | `/bin/bash` | Cloud-native paths |

**Translation Rules Engine:**
```yaml
# Conceptual rules file
commands:
  ping:
    linux_bash: "ping -c {count} {target}"
    linux_zsh: "ping -c {count} {target}"
    macos: "ping -c {count} {target}"
    windows_cmd: "ping -n {count} {target}"
    windows_ps: "Test-NetConnection -ComputerName {target} -Count {count}"
    wsl: "wsl ping -c {count} {target}"

  list_files:
    unix: "ls -la {path}"
    windows_cmd: "dir {path}"
    windows_ps: "Get-ChildItem -Path {path} -Force"
```

### 8.3 Real-Time Output Streaming

**Aggregator Behavior:**
- Collects stdout from all active agents
- Prefixes output with agent ID: `[Agent 02: nmap] ...`
- Color-codes by agent (if terminal supports)
- Handles mixed output without interleaving corruption
- Detects agent death/crash and reports immediately

---

## Chapter 9: Collaboration & Integrations

### 9.1 Team Collaboration (`/collab`)

```
siyarix> /collab ssh user@teammate-server

[Siyarix] Establishing secure collaborative session...
[Siyarix] Connected to teammate-server.
[Siyarix] Synchronized contexts:
  • Tool registry (47 tools)
  • Persona: Bug Hunter
  • Session: sess_abc123

[Teammate] joined the session.
siyarix [collab]> scan xyz.com
```

**Collaboration Features:**
- Shared terminal view (both see same output)
- Synchronized tool registry
- Joint command approval (both must approve `PERMISSION` level commands)
- Session persistence (either can reconnect if disconnected)
- Chat overlay for coordination

**Security:**
- SSH tunnel encryption
- No shared credential exposure
- Individual API keys remain local

### 9.2 VS Code Integration (`/coder`)

```
siyarix> /coder

[Siyarix] VS Code bridge active.
[Siyarix] Workspace: /home/user/siyarix-session-abc123
[Siyarix] File watcher initialized.
```

**Capabilities:**
- Generated scripts open in VS Code editor
- Real-time file sync between Siyarix and VS Code
- Diff review before execution
- Multi-file project generation
- Syntax highlighting for generated code
- Breakpoint-style step-through execution

### 9.3 MCP Server Integration (Research Mode)

```
siyarix> /work-mode research

[Siyarix] MCP (Model Context Protocol) servers enabled.
[Siyarix] Available MCP servers:
  1. vuln-db (local CVE database)
  2. threat-intel (MISP feed)
  3. exploit-db (Exploit-DB mirror)
  4. custom-corp (Company internal KB)

[Siyarix] Connecting to configured endpoints...
[Siyarix] Research mode active. External intelligence available.
```

**MCP Use Cases:**
- Query private vulnerability databases
- Integrate threat intelligence feeds
- Access internal company knowledge bases
- Connect to academic research repositories
- Air-gapped intelligence operations

---

## Chapter 10: Learning & Pedagogy

### 10.1 Tool Learning Mode

**Activation:** `/config learning tool on`

**What It Learns:**
- Successful command patterns per task type
- User corrections to AI-generated commands
- Platform-specific optimizations
- Tool flag effectiveness
- Execution timing (fast vs. thorough)

**Storage:**
- Local SQLite database: `~/.siyarix/memory/tool_patterns.db`
- Pattern format: `{task_type, persona, input_pattern, command, success_rate, user_correction}`

**Example Learning Event:**
```
[Siyarix] Task: "Scan xyz.com for web vulns"
[Siyarix] Generated: nuclei -u xyz.com
[Siyarix] User modified: nuclei -u xyz.com -t ~/custom-templates/
[Siyarix] Result: 3 more findings than default.
[Siyarix] Learning: "Custom templates improve web vuln detection"
[Siyarix] Pattern saved. Future similar tasks will suggest custom templates.
```

### 10.2 User Learning Mode (Pedagogical)

**Activation:** `/config learning user on`

**Teaching Output Example:**
```
[Siyarix] Task complete. Educational breakdown:

═══════════════════════════════════════════════════
STEP 1: Host Discovery (nmap -sn 192.168.1.0/24)
═══════════════════════════════════════════════════

What happened:
  Nmap sent ICMP echo requests to 256 IP addresses.
  3 hosts responded: .1 (router), .10 (web server), .55 (workstation)

What it means:
  • 192.168.1.1 is likely your gateway — don't attack this
  • 192.168.1.10 has services running — investigate further
  • 192.168.1.55 might be a client — lower priority

═══════════════════════════════════════════════════
STEP 2: Port Scanning (nmap -sV 192.168.1.10)
═══════════════════════════════════════════════════

What happened:
  Found ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
  Service versions: OpenSSH 8.2p1, nginx 1.18.0

What it means:
  • SSH 8.2p1: Check CVE-2020-15778 (scp vulnerability)
  • nginx 1.18.0: Check for known misconfigurations
  • Web server present: Start web app testing

═══════════════════════════════════════════════════
STEP 3: Web Scanning (nuclei -u http://192.168.1.10)
═══════════════════════════════════════════════════

What happened:
  Detected: CVE-2021-23017 (nginx DNS resolver vulnerability)
  Severity: HIGH

What it means:
  • This is a real vulnerability affecting nginx 1.18.0
  • Impact: Potential denial of service or code execution
  • Next step: Verify with manual testing or search for PoC

═══════════════════════════════════════════════════
[Siyarix] Would you like a detailed explanation of any step? [1/2/3/n]: 
```

---

## Chapter 11: Logging & Audit

### 11.1 Session Log Structure

```json
{
  "session_id": "sess_abc123",
  "timestamp_start": "2026-05-24T02:30:00Z",
  "timestamp_end": "2026-05-24T03:15:00Z",
  "persona": "bug_hunter",
  "llm_provider": "gemini",
  "llm_model": "gemini-1.5-pro",
  "user": "analyst1",
  "commands": [
    {
      "id": 1,
      "timestamp": "2026-05-24T02:31:00Z",
      "input": "scan xyz.com for vulns",
      "masked_input": "scan example.com for vulns",
      "ai_plan": ["nmap -sV xyz.com", "nuclei -u xyz.com"],
      "approved": true,
      "execution_time_ms": 45000,
      "output_summary": "3 open ports, 1 CVE detected",
      "full_output_ref": "logs/sess_abc123/cmd_01_output.txt"
    }
  ],
  "tool_usage": {
    "nmap": 2,
    "nuclei": 3
  },
  "safety_events": [
    {
      "type": "permission_gate",
      "command": "nuclei -u xyz.com",
      "action": "auto_approved_after_10s"
    }
  ]
}
```

### 11.2 Log Export Formats

```
siyarix> /log export sess_abc123 --format markdown --output report.md
siyarix> /log export sess_abc123 --format json --output audit.json
siyarix> /log export sess_abc123 --format pdf --output client_report.pdf
siyarix> /log export sess_abc123 --format sarif --output findings.sarif
```

**Format Use Cases:**
- **Markdown:** Quick sharing, GitHub issues
- **JSON:** Programmatic processing, SIEM ingestion
- **PDF:** Client deliverables
- **SARIF:** Static analysis results interchange format (industry standard)

---

## Chapter 12: Plugin System

### 12.1 Plugin Architecture

```
┌────────────────────────────────────────┐
│           Plugin Manager               │
│  ┌─────────────────────────────────┐   │
│  │  discover()                     │   │
│  │  install(name, source)          │   │
│  │  remove(name)                   │   │
│  │  enable(name)                   │   │
│  │  disable(name)                  │   │
│  │  list()                         │   │
│  └─────────────────────────────────┘   │
└──────────────────┬─────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌────────┐   ┌────────┐   ┌────────┐
│Provider│   │Report  │   │Notify  │
│Plugin  │   │Plugin  │   │Plugin  │
└────────┘   └────────┘   └────────┘
```

### 12.2 Verified Plugin Commands

```
siyarix> /plugin search
siyarix> /plugin install <name>
siyarix> /plugin remove <name>
siyarix> /plugin list
siyarix> /plugin enable <name>
siyarix> /plugin disable <name>
```

### 12.3 Plugin Categories (Discovered & Suggested)

| Category | Examples | Status |
|----------|----------|--------|
| AI Providers | siyarix-openai, siyarix-gemini, siyarix-ollama | ✅ Verified |
| Report Generators | siyarix-report-pdf, siyarix-report-html | ⚠️ Suggested |
| Notifications | siyarix-discord, siyarix-slack, siyarix-email | ⚠️ Suggested |
| Ticketing | siyarix-jira, siyarix-github-issues | ⚠️ Suggested |
| Cloud Platforms | siyarix-aws, siyarix-azure, siyarix-gcp | ⚠️ Suggested |
| Container Security | siyarix-docker, siyarix-kubernetes | ⚠️ Suggested |
| Compliance | siyarix-pci-dss, siyarix-iso27001 | ⚠️ Suggested |
| Custom Parsers | User-created tool output parsers | ⚠️ Suggested |

---

## Chapter 13: Cross-Platform Support

### 13.1 Platform Matrix

| OS | Shells | Terminals | Status | Notes |
|----|--------|-----------|--------|-------|
| Kali Linux | Bash, Zsh, Fish | Konsole, GNOME Terminal, Tmux |  | 600+ tools pre-installed |
| Ubuntu/Debian | Bash, Zsh | GNOME Terminal, Tilix | l | Standard security setup |
| macOS | Zsh, Bash | Terminal.app, iTerm2, Hyper |  | Homebrew integration |
| Windows 10/11 | CMD, PowerShell, PS Core | Windows Terminal, ConEmu |  | WSL bridge available |
| Windows WSL | Bash, Zsh | Windows Terminal |  | Linux tools via WSL |
| HarmonyOS | Terminal app | Built-in |  | Mobile/IoT context |
| GitHub Codespaces | Bash, Zsh | Web-based VS Code terminal |  | Containerized |
| Google Cloud Shell | Bash | Web-based |  | Ephemeral storage |
| AWS CloudShell | Bash | Web-based |  | AWS-native tools |

### 13.2 Terminal Detection Logic

```python
# Conceptual detection
def detect_terminal():
    env_shell = os.environ.get('SHELL', '')
    env_term = os.environ.get('TERM', '')
    env_program = os.environ.get('TERM_PROGRAM', '')

    if 'zsh' in env_shell:
        return Terminal.ZSH
    elif 'bash' in env_shell:
        return Terminal.BASH
    elif 'powershell' in env_shell.lower() or 'pwsh' in env_shell.lower():
        return Terminal.POWERSHELL
    elif os.name == 'nt' and not env_shell:
        return Terminal.CMD
    elif 'tmux' in env_term:
        return Terminal.TMUX
    elif env_program == 'iTerm.app':
        return Terminal.ITERM2
    elif env_program == 'Apple_Terminal':
        return Terminal.TERMINAL_APP
    else:
        return Terminal.GENERIC
```

---

# PART II: ADVANCED OPERATIONAL WORKFLOWS

---

## Chapter 14: Complete Command Lifecycle (End-to-End)

### 14.1 Scenario: Bug Bounty Reconnaissance

**User:** Bug hunter persona, Gemini provider, Kali Linux

```
siyarix> /work-mode bug hunter
[Siyarix] Persona: Bug Hunter
[Siyarix] Tool filter: 23 web-focused tools active

siyarix> scan xyz.com for vulnerabilities

[Siyarix] Task received. Planning...
[Siyarix] Masking: xyz.com → example.com
[Siyarix] Sending to Gemini...

[AI Plan - Masked]:
  1. subfinder -d example.com -o subs.txt
  2. cat subs.txt | httpx -o live.txt
  3. nuclei -l live.txt -t cves/ -severity critical,high
  4. ffuf -u http://example.com/FUZZ -w wordlist.txt

[Siyarix] Response sensor: All commands allowed
[Siyarix] Unmasking: example.com → xyz.com

[Siyarix] Spawning sub-agents...
[Agent 01] subfinder -d xyz.com -o subs.txt
[Agent 01] Found: 15 subdomains

[Agent 02] cat subs.txt | httpx -o live.txt
[Agent 02] Live hosts: 12

[Agent 03] nuclei -l live.txt -t cves/ -severity critical,high
[Agent 03] [CVE-2023-XXXX] http://api.xyz.com
[Agent 03] [CVE-2022-YYYY] http://admin.xyz.com

[Agent 04] ffuf -u http://xyz.com/FUZZ -w wordlist.txt
[Agent 04] /admin [302]
[Agent 04] /api/v1 [200]
[Agent 04] /.env [200] ⚠️

[Siyarix] Task complete. 2 CVEs, 1 exposed .env file found.
[Siyarix] Learning mode: Storing patterns...
[Siyarix] Log saved: sess_def456
```

### 14.2 Scenario: Incident Response (SOC Mode)

**User:** SOC analyst persona, local Ollama, Ubuntu

```
siyarix> /work-mode soc
[Siyarix] Persona: SOC Analyst
[Siyarix] Tool filter: 18 monitoring/forensics tools active

siyarix> investigate alert ALERT-2026-001

[Siyarix] Loading alert context...
[Siyarix] Plan:
  1. Query SIEM for related events
  2. Check endpoint EDR logs
  3. Analyze suspicious process
  4. Check network connections
  5. Generate incident timeline

[Agent 01] sigma query: title:"Suspicious PowerShell"
[Agent 01] 47 matching events in last 24h

[Agent 02] velociraptor hunt: ProcessName=powershell.exe
[Agent 02] 3 endpoints affected

[Agent 03] volatility -f memory.dump pslist
[Agent 03] Suspicious: powershell.exe PID 4521 (injected)

[Siyarix] Escalation recommended: Confirmed compromise
[Siyarix] Timeline generated. Report: /tmp/incident_ALERT-001.md
```

---

## Chapter 15: Hidden Features & Discovery Guide

### 15.1 Necessary Capabilities

| Feature | How to Access | Documantation | Complexity |
|---------|--------------|---------------|------------|
| First-run bootstrap | Just run `siyarix` | README | Low |
| Custom persona builder | `/work-mode create` | User | Medium |
| Auto persona detection | `/work-mode auto` | User | Low |
| Tool ACL config | `/config tool access` | User | Medium |
| Lazy module loading | `/key set <new-provider>` | User | Low |
| Collaborative sessions | `/collab ssh` | User | Medium |
| VS Code bridge | `/coder` | User | Medium |
| MCP integration | `/mode research` | User | High |
| Session logging | `/log <id>` | User | Low |
| ESC kill switch | Press `ESC` | User | Low |
| Custom masking rules | `/config masking` | Inferred | Medium |
| Plugin marketplace | `/plugin` | User | Medium |
| Batch mode / scripting | `siyarix --batch` or `/batch` | Try `siyarix --help` for hidden flags |
| Configuration profiles | `~/.siyarix/profiles/` | Check directory structure |
| Environment variables | `.env` support | Create `.env` with `SIYARIX_DEBUG=1` |
| API mode (REST) | `siyarix --server` or similar | Try port scanning localhost after launch |
| Scheduled tasks | `/schedule` or cron integration | Try `/schedule` command |
| Import/export personas | `/work-mode export` | Try `/work-mode export my-persona` |
| Diff mode (compare scans) | `/diff` or `--compare` | Try `/diff sess_abc123 sess_def456` |
| Stealth/Evasion mode | `/config stealth` or similar | Try `/config` and look for stealth options |
| Reporting templates | `~/.siyarix/templates/` | Check for template directory |
| Multi-target mode | `@targets.txt` syntax | Try `siyarix scan @targets.txt` |

# PART III: SUGGESTED ENHANCEMENTS & ROADMAP

---

## Chapter 16: AI & Intelligence Enhancements

### 16.1 Multi-Model Ensemble (Suggested)

**Concept:** Route tasks to multiple LLMs simultaneously and vote on best plan.

```
User: "Scan xyz.com"
    │
    ├──→ GPT-4 Turbo ──→ Plan A
    ├──→ Gemini Pro ───→ Plan B
    ├──→ Local Llama3 ──→ Plan C
    │
    ▼
┌─────────────────────────┐
│   Plan Aggregator       │
│  • Compare coverage     │
│  • Detect hallucinations│
│  • Select optimal plan  │
│  • Or merge best parts  │
└─────────────────────────┘
```

**Benefits:**
- Reduces hallucination risk
- Cross-validates tool selection
- Optimizes for cost (cheap model for simple tasks, expensive for complex)

### 16.2 Chain-of-Thought Visualization (Suggested)

**Feature:** Show the AI's reasoning process in real-time.

```
[Siyarix] Thinking...
  ├─→ "User wants vulnerability assessment"
  ├─→ "Target is a domain (xyz.com)"
  ├─→ "Bug Hunter persona active"
  ├─→ "Web-focused tools available: nuclei, ffuf, httpx"
  ├─→ "Plan: subdomain enum → live check → CVE scan → content discovery"
  └─→ "Estimated time: 5 minutes"

[Siyarix] Plan confirmed. Executing...
```

### 16.3 Adversarial Testing Mode (Suggested)

**Concept:** AI actively tries to find flaws in its own plan before execution.

```
[Siyarix] Plan generated. Running adversarial review...
  ⚠️ "nmap -sV may trigger IDS — suggest stealth scan?"
  ⚠️ "ffuf rate not limited — may cause DoS"
  ✓ "nuclei templates cover latest CVEs"

[Siyarix] Apply adversarial suggestions? [Y/n]: Y
[Siyarix] Plan updated: Added `-T2` to nmap, added `-rate 100` to ffuf
```

### 16.4 Context Window Compression (Suggested)

**Problem:** Long sessions exceed LLM context limits.

**Solution:** Automatic summarization of session history.

```
[Siyarix] Context window 85% full. Compressing history...
[Siyarix] Summary: "So far: discovered 15 subdomains, found 2 CVEs, 
          currently fuzzing directories. Next: verify findings."
```

### 16.5 Few-Shot Learning from Community (Suggested)

**Concept:** Opt-in sharing of successful command patterns (anonymized).

```
[Siyarix] Community insight: 847 users found that adding 
          `--tags cve` to nuclei improves CVE detection by 23%.
[Siyarix] Apply this insight? [Y/n]: Y
```

---

## Chapter 17: Operational & Workflow Enhancements

### 17.1 Playbook System (Suggested)

**Concept:** Save and replay complex multi-step workflows.

```
siyarix> /playbook save bugbounty-recon

[Siyarix] Playbook "bugbounty-recon" saved:
  Step 1: subfinder -d {target}
  Step 2: httpx -l subs.txt
  Step 3: nuclei -l live.txt -t cves/
  Step 4: ffuf -u {target}/FUZZ

siyarix> /playbook run bugbounty-recon --target xyz.com
```

**Playbook Features:**
- Variables: `{target}`, `{wordlist}`, `{severity}`
- Conditionals: `if port_80_open then run ffuf`
- Loops: `for each subdomain in subs.txt`
- Error handling: `on_error: skip_and_log`

### 17.2 Scheduled / Recurring Scans (Suggested)

```
siyarix> /schedule create daily-health-check

Target: xyz.com
Frequency: Daily at 02:00 UTC
Persona: Defensive
Command: "run basic health check on xyz.com"
Alert on: New open ports, new CVEs, SSL expiry < 30 days
Notify: /notify email security@company.com

[Siyarix] Scheduled. Next run: 2026-05-25 02:00 UTC
```

### 17.3 Baseline Deviation Detection (Suggested)

**Concept:** Learn "normal" state, alert on changes.

```
[Siyarix] Baseline established for xyz.com:
  • Ports: 80, 443
  • Technologies: nginx 1.18, PHP 7.4
  • Headers: X-Frame-Options present

[Siyarix] Daily scan deviation detected:
  • NEW: Port 8080 open (Tomcat)
  • NEW: Header X-Frame-Options missing
  • CHANGED: nginx 1.18 → 1.19

[Siyarix] Alert: 3 deviations from baseline. Review? [Y/n]: Y
```

### 17.4 Evidence Preservation Chain (Suggested)

**For professional engagements:**

```
[Siyarix] Evidence mode enabled.

All outputs will be:
  • Cryptographically hashed (SHA-256)
  • Timestamped (RFC 3161 timestamp token)
  • Signed (GPG / x.509)
  • Stored in tamper-evident log

Evidence ID: EVID-2026-001
Court-admissible: Yes (with notarization plugin)
```

### 17.5 Multi-Target Campaign Mode (Suggested)

```
siyarix> /campaign create client-assessment

Targets: @client-targets.txt (50 domains)
Persona: Pentester
Scope: Recon + Light touch only
Rate limit: 1 request/second per target
Concurrent targets: 5
Report template: /templates/pentest-report.md

[Siyarix] Campaign launched. 50 targets queued.
[Siyarix] Progress: [=====>    ] 12/50 complete
```

---

## Chapter 18: Reporting & Deliverables

### 18.1 Report Templates (Suggested)

```
siyarix> /report generate --template bugbounty

Sections:
  1. Executive Summary
  2. Scope & Methodology
  3. Findings (CVSS scored)
  4. Evidence Screenshots
  5. Remediation Guidance
  6. Retest Verification
  7. Appendix: Tool Output

Format: PDF (with plugin: siyarix-report-pdf)
       HTML (with plugin: siyarix-report-html)
       DOCX (with plugin: siyarix-report-docx)
```

### 18.2 CVSS Auto-Scoring (Suggested)

```
[Siyarix] Finding: SQL Injection in search parameter
[Siyarix] Auto-calculating CVSS 3.1...
  • Attack Vector: Network → AV:N
  • Attack Complexity: Low → AC:L
  • Privileges Required: None → PR:N
  • User Interaction: None → UI:N
  • Scope: Changed → S:C
  • Confidentiality: High → C:H
  • Integrity: High → I:H
  • Availability: Low → A:L

[Siyarix] CVSS Score: 9.9 (Critical)
```

### 18.3 Remediation Guidance Generation (Suggested)

```
[Siyarix] Remediation for CVE-2023-XXXX:

Priority: CRITICAL
Effort: Low (1-2 hours)

Steps:
  1. Update nginx to 1.24.0 or later
  2. Verify fix: nginx -v
  3. Regression test: nuclei -u xyz.com -t cves/CVE-2023-XXXX.yaml

Code snippet:
  ```bash
  apt update && apt install nginx
  systemctl restart nginx
  ```

Verification command:
  nuclei -u xyz.com -id CVE-2023-XXXX
```

### 18.4 Client Portal Integration (Suggested)

```
siyarix> /report publish --portal client-portal

[Siyarix] Uploading to client portal...
[Siyarix] Report ID: RPT-2026-001
[Siyarix] Client access: https://portal.company.com/reports/RPT-2026-001
[Siyarix] Expires: 30 days
[Siyarix] Password protected: Yes
```

---

## Chapter 19: Team & Enterprise Features

### 19.1 Role-Based Access Control (RBAC) (Suggested)

```
siyarix> /team rbac create-role junior-analyst

Permissions:
  • Personas: bug_hunter, defensive
  • Forbidden tools: metasploit, sqlmap
  • Max auto-approve: None (always require approval)
  • Can view logs: Own only
  • Can collaborate: Yes
  • Can install plugins: No

siyarix> /team rbac assign junior-analyst @alice
```

### 19.2 Team Dashboard (Suggested)

```
siyarix> /team dashboard

┌──────────────────────────────────────────────┐
│  Siyarix Team Dashboard - Security Ops       │
├──────────────────────────────────────────────┤
│ Active Sessions: 4                           │
│ Active Campaigns: 1 (client-assessment)      │
│ Findings Today: 23 (5 Critical, 12 High)     │
│ Alerts: 2 (deviation from baseline)          │
│                                              │
│ Team Members:                                │
│   Alice [Bug Hunter] ──→ scan in progress    │
│   Bob [SOC] ─────────→ investigating ALERT-3 │
│   Carol [Pentester] ───→ report generation   │
│   Dave [Admin] ───────→ system maintenance   │
└──────────────────────────────────────────────┘
```

### 19.3 Knowledge Base Sharing (Suggested)

```
siyarix> /kb share --team security-ops

Sharing:
  • Custom personas (3)
  • Tool ACL profiles (2)
  • Successful patterns (47)
  • Custom masking rules (5)

[Siyarix] Knowledge base synchronized.
[Siyarix] 4 team members updated.
```

### 19.4 Integration with Ticketing Systems (Suggested)

```
siyarix> /ticket create --jira

Project: SEC
Issue Type: Vulnerability
Summary: [CRITICAL] SQL Injection in xyz.com/search
Priority: P1
Assignee: @security-team
Labels: auto-discovered, siyarix, needs-triage

[Siyarix] Jira ticket SEC-2847 created.
[Siyarix] Link: https://jira.company.com/browse/SEC-2847
```

### 19.5 SSO & Authentication (Suggested)

```
siyarix> /auth sso configure --provider okta

[Siyarix] SSO enabled.
[Siyarix] MFA required for destructive operations.
[Siyarix] Session timeout: 8 hours.
```

---

## Chapter 20: Advanced Security & Hardening

### 20.1 Deception & Evasion Mode (Suggested)

```
siyarix> /config stealth on

Stealth features activated:
  • Randomized User-Agent rotation
  • Request jitter (±30% delay)
  • Distributed requests across TOR exit nodes
  • CloudFront/CloudFlare origin bypass techniques
  • Timing randomization between sub-agents
  • Decoy traffic generation (noise)

[Siyarix] Stealth score: 8.5/10 (IDS evasion likely)
```

### 20.2 Canary Token Integration (Suggested)

```
siyarix> /canary deploy --target xyz.com

Deployed:
  • /admin.bak (fake backup, alerts on access)
  • /config.json (fake AWS keys, alerts on use)
  • /debug.php (fake debug endpoint, alerts on visit)

[Siyarix] Canary tokens active. Alerts to: security@company.com
```

### 20.3 Threat Intelligence Correlation (Suggested)

```
siyarix> /intel query --ioc 192.168.1.100

Threat Intelligence Correlation:
  • AbuseIPDB: Reported 47 times (Brute force)
  • VirusTotal: 3/90 engines flag as malicious
  • AlienVault OTX: Linked to APT29
  • MISP: Matches campaign "Winter-2026"

[Siyarix] HIGH CONFIDENCE: Malicious IP. Block recommended.
```

### 20.4 Automated Retest & Regression (Suggested)

```
siyarix> /retest schedule --finding CVE-2023-XXXX

Target: xyz.com
Frequency: Weekly
Alert on: Still vulnerable
Auto-close: If fixed for 4 consecutive weeks

[Siyarix] Retest scheduled. Next: 2026-05-31
```

### 20.5 Secure Multi-Party Computation (Suggested)

**For sensitive collaborative assessments:**

```
siyarix> /collab mpc --parties 3

Secure MPC session:
  • Party 1: Client (shares target list)
  • Party 2: Auditor (shares methodology)
  • Party 3: Siyarix (orchestrates)

No single party sees full picture.
Results computed cryptographically.
```

---

## Chapter 21: Cloud & Container Ecosystem

### 21.1 Cloud Provider Native Integration (Suggested)

| Provider | Integration | Commands |
|----------|-------------|----------|
| **AWS** | IAM role assumption, CloudTrail analysis | `siyarix cloud aws scan --account 123456` |
| **Azure** | AAD integration, Activity Log analysis | `siyarix cloud azure scan --subscription xxx` |
| **GCP** | Service account auth, Cloud Audit Logs | `siyarix cloud gcp scan --project my-project` |
| **Kubernetes** | In-cluster scanning, RBAC analysis | `siyarix k8s scan --namespace default` |
| **Docker** | Image scanning, runtime analysis | `siyarix docker scan --image nginx:latest` |

### 21.2 Infrastructure as Code Security (Suggested)

```
siyarix> /iac scan --path ./terraform/

Scanning:
  • main.tf: S3 bucket public access detected
  • security.tf: Security group allows 0.0.0.0/0:22
  • iam.tf: Overly permissive IAM policy

[Siyarix] 3 misconfigurations. Fix suggestions available.
```

### 21.3 CI/CD Pipeline Integration (Suggested)

```yaml
# .github/workflows/security.yml
name: Siyarix Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Siyarix
        uses: siyarix/action@v1
        with:
          persona: 'defensive'
          target: 'http://localhost:8080'
          fail-on: 'critical'
```

---

## Chapter 22: Mobile & IoT Extensions

### 22.1 Mobile Application Testing (Suggested)

```
siyarix> /mobile android --apk app.apk

[Siyarix] Decompiling APK...
[Siyarix] Running static analysis...
[Siyarix] Findings:
  • Hardcoded API key in strings.xml
  • Insecure network security config
  • Debug flag enabled in release build

[Siyarix] Dynamic testing with Frida hooks available.
```

### 22.2 IoT & Embedded Device Testing (Suggested)

```
siyarix> /iot scan --device /dev/ttyUSB0

[Siyarix] Detected: ESP32 device
[Siyarix] Firmware extraction...
[Siyarix] Findings:
  • UART debug interface active
  • Hardcoded credentials: admin/admin
  • No secure boot enabled
  • OTA update over HTTP (not HTTPS)
```

### 22.3 Hardware Security Module (HSM) Integration (Suggested)

```
siyarix> /hsm configure --provider yubikey

[Siyarix] YubiKey detected.
[Siyarix] API key storage moved to HSM.
[Siyarix] All cryptographic operations now hardware-backed.
```

---

## Chapter 23: Gamification & Community [only if learing user mode on]

### 23.1 Achievement System (Suggested)

```
[Siyarix] 🏆 Achievement Unlocked: "First Blood"
    Discovered your first critical vulnerability!

[Siyarix] 🏆 Achievement Unlocked: "Tool Master"
    Used 50+ different security tools.

[Siyarix] 🏆 Achievement Unlocked: "Stealth Operator"
    Completed 10 scans without triggering IDS.
```

### 23.2 Community Challenges (Suggested)

```
siyarix> /challenge join weekly-ctf

[Siyarix] Weekly CTF Challenge:
    Target: ctf.siyarix.community
    Goal: Find the flag
    Time limit: 48 hours
    Hints: 3 available

[Siyarix] Your rank: #23 / 1,247 participants
```

---

# PART IV: SECURITY HARDENING & COMPLIANCE

---

## Chapter 24: Compliance Frameworks

### 24.1 Built-in Compliance Modules (Suggested)

| Framework | Plugin | Coverage |
|-----------|--------|----------|
| PCI-DSS | siyarix-pci-dss | Requirement 6, 11 |
| ISO 27001 | siyarix-iso27001 | A.12.6, A.14.2 |
| NIST 800-53 | siyarix-nist-800-53 | RA-5, SI-4 |
| SOC 2 | siyarix-soc2 | CC7.1, CC7.2 |
| GDPR | siyarix-gdpr | Article 32 |
| HIPAA | siyarix-hipaa | 164.308, 164.312 |

```
siyarix> /compliance run --framework pci-dss --target xyz.com

[Siyarix] PCI-DSS Assessment initiated.
[Siyarix] Checking Requirement 6.5 (Address common coding vulnerabilities)...
[Siyarix] Checking Requirement 11.3 (Penetration testing)...

[Siyarix] Compliance Report:
  • Compliant: 8/12 requirements
  • Non-compliant: 3/12 (with remediation)
  • Not applicable: 1/12
```

### 24.2 Audit Trail & Non-Repudiation (Suggested)

```
siyarix> /audit export --case legal-proceeding-2026

Export includes:
  • All commands with cryptographic hashes
  • Timestamped execution records
  • User identity (SSO-attested)
  • LLM provider and model version
  • Tool versions used
  • Output integrity verification
  • GPG-signed manifest

Admissible in court: Yes (with notarization)
```

---

## Chapter 25: Operational Security (OPSEC)

### 25.1 Target Isolation (Suggested)

```
siyarix> /opsec isolate --target xyz.com

Isolation measures:
  • Dedicated network namespace
  • TOR exit node rotation
  • DNS over HTTPS (DoH)
  • MAC address randomization
  • No persistent logs for this target
  • Memory-only operation mode
```

### 25.2 Burn After Reading (Suggested)

```
siyarix> /opsec burn --session sess_abc123

[Siyarix] Secure deletion initiated...
  • Log files: 37 files shredded (3-pass Gutmann)
  • Memory: Secure zeroization
  • Disk cache: Flushed and overwritten
  • Network traces: Cleared

[Siyarix] Session sess_abc123 irrecoverably destroyed.
```

---

# PART V: INTEGRATION ECOSYSTEM

---

## Chapter 26: External Platform Integrations

### 26.1 Bug Bounty Platforms (Suggested)

```
siyarix> /platform connect --hackerone

[Siyarix] OAuth to HackerOne...
[Siyarix] Connected as: @your-handle

siyarix> /platform submit --program target-com --finding finding_001

[Siyarix] Submitting to HackerOne...
[Siyarix] Report ID: H1-284756
[Siyarix] Status: Triaged
```

### 26.2 SIEM & SOAR Integration (Suggested)

```
siyarix> /siem connect --splunk https://splunk.company.com:8089

[Siyarix] Connected to Splunk.
[Siyarix] Forwarding findings in real-time...

[Siyarix] SOAR playbook triggered:
  • High-severity finding → Auto-create ticket
  • Critical finding → Page on-call engineer
  • Confirmed breach → Isolate endpoint
```

### 26.3 Communication Platforms (Suggested)

| Platform | Plugin | Use Case |
|----------|--------|----------|
| Slack | siyarix-slack | Team notifications |
| Discord | siyarix-discord | Community alerts |
| Microsoft Teams | siyarix-teams | Enterprise notifications |
| Telegram | siyarix-telegram | Mobile alerts |
| PagerDuty | siyarix-pagerduty | On-call paging |
| Email | siyarix-email | Formal reporting |

---

## Chapter 27: Data Format Interoperability

### 27.1 Import/Export Formats (Suggested)

| Format | Import | Export | Use Case |
|--------|--------|--------|----------|
| JSON | ✅ | ✅ | API integration |
| XML | ✅ | ✅ | Legacy systems |
| CSV | ✅ | ✅ | Spreadsheet analysis |
| SARIF | ✅ | ✅ | Static analysis standard |
| STIX/TAXII | ✅ | ✅ | Threat intelligence |
| OpenIOC | ✅ | ✅ | IOC sharing |
| YAML | ✅ | ✅ | Configuration management |
| Nessus | ✅ | ❌ | Import Nessus scans |
| Burp | ✅ | ❌ | Import Burp Suite state |
| Metasploit | ✅ | ❌ | Import MSF database |

---

# PART VI: PERFORMANCE & SCALABILITY

---

## Chapter 28: Performance Optimization

### 28.1 Resource-Based Agent Scaling (Suggested)

```
siyarix> /performance configure

System Resources:
  • CPU: 16 cores detected
  • RAM: 32GB detected
  • Network: 1Gbps

Agent Pool Configuration:
  • Max concurrent agents: 15 → [Change]
  • Memory limit per agent: 2GB
  • CPU affinity: Auto-balanced
  • Network throttling: Disabled

[Siyarix] Optimized for your hardware.
```

### 28.2 Distributed Execution (Suggested)

```
siyarix> /distributed configure

Worker Nodes:
  • localhost (16 cores, 32GB)
  • worker-2.company.local (8 cores, 16GB)
  • worker-3.company.local (8 cores, 16GB)

Task Distribution:
  • Subdomain enumeration → worker-2
  • Port scanning → worker-3
  • Web scanning → localhost
  • Report generation → localhost

[Siyarix] Distributed cluster active. 40 cores available.
```

### 28.3 Caching & Memoization (Suggested)

```
siyarix> /cache status

Cache Statistics:
  • Tool output cache: 1.2GB (234 entries)
  • AI plan cache: 45MB (89 entries)
  • WHOIS cache: 12MB (340 entries)
  • DNS cache: 8MB (567 entries)

Hit rate: 67% (saving ~45 minutes per session)
```

---

# APPENDICES

---

## Appendix A: Complete Command Reference

### A.1 Terminal Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `siyarix` | None | Launch interactive chat mode |
| `siyarix scan` | `<target>` | Quick network scan |
| `siyarix run` | `"<natural language>"` | Execute NL task |
| `siyarix tool-registry` | `list/run <tool>` | Direct tool access |
| `siyarix --version` | None | Show version |
| `siyarix --help` | None | Show help (may have hidden flags) |
| `siyarix --config` | `<path>` | Specify config file |
| `siyarix --batch` | `<script>` | *(Suggested)* Batch mode |

### A.2 Interactive Slash Commands (Necessary)

| Command | Sub-commands | Description |
|---------|-------------|-------------|
| `/work-mode` | `<mode>/create/auto/none` | Switch or create persona |
| `/config` | `tool/safety/learning/masking` | Configuration hub |
| `/key` | `set/rotate/remove/list` | AI provider management |
| `/model` | `set <provider> <model>` | Model selection |
| `/plugin` | `search/install/remove/list` | Plugin marketplace |
| `/collab` | `ssh/disconnect/status` | Team collaboration |
| `/coder` | `(sec)/disconnect` | VS Code integration |
| `/mode` | `research/standard` | MCP research mode |
| `/log` | `list/view/export` | Session logging |
| `/theme` | `mode dark/light` | UI theme |
| `/help` | None | Context-sensitive help |
| `/bye` | None | Save and exit |

### A.3 Interactive Slash Commands (Suggested)

| Command | Description | Priority |
|---------|-------------|----------|
| `/playbook` | Save/load workflow playbooks | High |
| `/schedule` | Create recurring tasks | High |
| `/campaign` | Multi-target batch operations | High |
| `/report` | Generate formatted reports | High |
| `/team` | RBAC and team management | Medium |
| `/kb` | Knowledge base operations | Medium |
| `/ticket` | Create tickets in external systems | Medium |
| `/retest` | Schedule verification scans | Medium |
| `/intel` | Threat intelligence queries | Medium |
| `/canary` | Deploy deception tokens | Low |
| `/stealth` | Evasion configuration | Low |
| `/audit` | Compliance and legal export | Medium |
| `/opsec` | Operational security measures | Low |
| `/performance` | Resource optimization | Low |
| `/distributed` | Multi-node execution | Low |
| `/cache` | Cache management | Low |
| `/challenge` | Community CTF participation | Fun |
| `/community` | Leaderboard and sharing | Fun |
| `/mobile` | Mobile app testing | Medium |
| `/iot` | Embedded device testing | Low |
| `/cloud` | Cloud provider scanning | High |
| `/k8s` | Kubernetes security | Medium |
| `/docker` | Container scanning | Medium |
| `/iac` | Infrastructure as Code scan | Medium |
| `/compliance` | Framework assessment | Medium |
| `/hsm` | Hardware security module | Low |
| `/platform` | Bug bounty submission | Medium |
| `/siem` | SIEM/SOAR integration | Medium |

---

## Appendix B: Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `SIYARIX_CONFIG` | Config file path | `~/.siyarix/config.yaml` |
| `SIYARIX_HOME` | Data directory | `~/.siyarix/` |
| `SIYARIX_DEBUG` | Debug mode | `1` |
| `SIYARIX_PERSONA` | Default persona | `bug_hunter` |
| `SIYARIX_PROVIDER` | Default AI provider | `ollama` |
| `SIYARIX_TIMEOUT` | Global timeout | `300` (seconds) |
| `SIYARIX_LOG_LEVEL` | Logging verbosity | `INFO` |
| `SIYARIX_NO_TELEMETRY` | Disable analytics | `1` |
| `SIYARIX_SAFE_MODE` | Paranoid safety profile | `1` |

---

## Appendix C: File Structure

```
~/.siyarix/
├── config.yaml              # Main configuration
├── .initialized             # First-run marker
├── personas/
│   ├── bug_hunter.yaml
│   ├── pentester.yaml
│   └── custom/
│       └── api_hunter.yaml
├── plugins/
│   ├── installed/
│   └── available/
├── memory/
│   ├── tool_patterns.db     # Tool learning data
│   └── user_progress.db     # User learning data
├── logs/
│   ├── sessions/
│   │   ├── sess_abc123/
│   │   │   ├── metadata.json
│   │   │   ├── commands.json
│   │   │   └── outputs/
│   │   └── sess_def456/
│   └── audit/
├── vault/
│   └── keys.enc             # Encrypted API keys
├── cache/
│   ├── tool_outputs/
│   ├── ai_plans/
│   └── dns/
├── templates/
│   ├── reports/
│   └── playbooks/
└── masking/
    └── custom_rules.yaml
```

---

## Appendix E: Glossary

| Term | Definition |
|------|------------|
| **Agent** | Autonomous software entity that perceives and acts |
| **ACL** | Access Control List — permissions for tools |
| **MCP** | Model Context Protocol — external tool integration standard |
| **OPSEC** | Operational Security — protecting sensitive information |
| **Persona** | Behavioral profile defining how Siyarix operates |
| **REPL** | Read-Eval-Print Loop — interactive command interface |
| **SARIF** | Static Analysis Results Interchange Format |
| **Sub-Agent** | Worker process executing a specific task |
| **WSL** | Windows Subsystem for Linux |

---

## Appendix F: Troubleshooting Quick Reference

| Symptom | Likely Cause | Solution |
|---------|-------------|----------|
| "Module not found" on `/key set` | Lazy loading | Approve installation prompt |
| Auto mode very slow | Classification overhead | Switch to manual `/work-mode` |
| Commands not executing | Tool ACL set to OFF | `/config tool access` → enable |
| Real targets in LLM logs | Masking not configured | `/config masking` → add rules |
| ESC not working | Terminal capture issue | Try `Ctrl+C` as fallback |
| Plugin install fails | Network/permission | Check `pip` permissions |
| Session not saving | Disk space/permissions | Check `~/.siyarix/logs/` writable |
| VS Code not connecting | Extension missing | Install Siyarix VS Code extension |
| Collaboration timeout | SSH/firewall | Check port 22 and network |

---
