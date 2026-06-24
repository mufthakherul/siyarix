# ⚙️ Execution Engine

The execution subsystem is the beating heart of Siyarix. It takes abstract `ExecutionPlan` objects and transforms them into real-world, executed commands. Built on a robust, layered architecture, it features a shared **BaseExecutor** that provides critical services like budget tracking, safety guardrails, Data Loss Prevention (DLP) integration, and strict permission gating for all specialized executors.

> [!NOTE]
> The Execution Engine ensures that every action Siyarix takes is safe, tracked, and within defined operational boundaries.

---

## 🏗️ Architecture Overview

The system uses a parent-child inheritance model where the `BaseExecutor` handles the heavy lifting of security and limits, allowing specialized executors to focus on running commands.

```text
ExecutionPlan (from Planner)
         │
         ▼
┌───────────────────────────────────────────────────────────┐
│                   BaseExecutor                            │
│                                                           │
│  Shared across all executor variants:                     │
│  • ExecutionBudget (iterations, tool calls, duration)     │
│  • ToolCallTracker (failure counting, guardrails)         │
│  • PermissionGate integration (BLOCK/REVIEW/ALLOW)        │
│  • DLP Engine redaction on tool results                   │
│  • AsyncWorkerPool for bounded concurrency                │
│  • EventBus integration for step lifecycle events         │
└───────────────────────┬───────────────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
   ┌────────────┐ ┌────────────┐ ┌────────────┐
   │ Registry   │ │Autonomous  │ │ Validator  │
   │ Executor   │ │ Executor   │ │ (recovery) │
   │ (ToolReg)  │ │(shell cmd) │ │            │
   └────────────┘ └────────────┘ └────────────┘
          │             │             │
          ▼             ▼             ▼
   AsyncWorkerPool  Tool Parsers  KnowledgeGraph
```

---

## 📋 Plan Structure

At the core of the engine is the `ExecutionPlan`, a data structure that dictates what needs to be done, how, and in what order.

> [!IMPORTANT]
> A well-formed `ExecutionPlan` is crucial for successful execution. The `plan_type` determines how the engine approaches the tasks (e.g., sequentially or via a complex DAG).

### 📝 ExecutionPlan

```python
@dataclass
class ExecutionPlan:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    goal: str = ""
    plan_type: PlanType               # SEQUENTIAL | PARALLEL | DAG | REACT | ADAPTIVE
    status: PlanStatus                # DRAFT | ACTIVE | PAUSED | COMPLETED | FAILED | CANCELLED
    steps: list[PlanStep]
    context: dict
    created_at: float
    metadata: dict
    raw_instruction: str = ""
    source: str = ""
    confidence: float = 1.0
```

### 🛠️ PlanStep

Each step within a plan represents a single actionable item.

```python
@dataclass
class PlanStep:
    id: str
    description: str
    tool: str
    args: dict
    command: str | None
    status: StepStatus                # PENDING | READY | RUNNING | COMPLETED | FAILED | SKIPPED | RETRYING | BLOCKED
    result: dict
    dependencies: list[str]
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 300.0
    duration_ms: float = 0.0
    metadata: dict
```

---

## 🛡️ Shared Infrastructure (`BaseExecutor`)

The `BaseExecutor` (found in `siyarix/executor.py`) acts as the parent class for all executors, providing a unified safety and performance net.

### 💰 ExecutionBudget
Tracks and enforces resource consumption to prevent runaway processes.

| Limit | Default | Description |
|-------|---------|-------------|
| `max_iterations` | 50 | Maximum planning/execution cycles allowed. |
| `max_tool_calls` | 100 | Maximum number of tool invocations. |
| `max_duration_s` | 600 | Maximum wall-clock execution time (in seconds). |

> [!WARNING]
> The budget is checked before *every* step. If any limit is exhausted, execution is halted immediately.

### 🚦 ToolCallTracker
Monitors how tools are performing and enforces guardrail policies to prevent spam or infinite loops.

| Guardrail | Threshold | Action |
|-----------|-----------|--------|
| **Exact failure warn** | 2 failures | Logs a warning for visibility. |
| **Exact failure block** | 5 failures | Blocks the tool from further use. |
| **Same-tool failure halt** | 8 consecutive | Halts the tool entirely. |
| **No-progress block** | 5 calls with identical args | Blocks the call to prevent looping. |

> [!TIP]
> Failure states are persisted to `tool_failures.json` to maintain context and safety across different sessions!

### 🔐 Permission Gate Integration
Every single step is scrutinized by the `PermissionGate` before it runs:
1. **Blocked:** If the command is on the blocklist, a `PermissionDeniedError` is raised.
2. **Review Required:** The engine pauses and invokes `review_and_confirm()` to get user approval.
3. **Resolution:** The user can approve, modify, or cancel the pending command.

### 🕵️‍♂️ DLP Redaction
Security doesn't stop at execution. Results are scrubbed by the `DLPEngine` to redact sensitive values (like API keys or PII) *before* they are saved to the KnowledgeGraph or session logs.

---

## 🚀 Executor Types

Siyarix provides specialized executors to handle different operational modes. The `AgentCore` dispatches work to the appropriate executor based on the current mode.

### 🧩 RegistryExecutor (`siyarix/executor_registry.py`)
Executes plan steps using predefined tools from the `ToolRegistry`. It features full guardrail protection and Dependency Graph (DAG) support.

- **Tool Dispatch:** Looks up and runs capabilities directly from the registry.
- **Parallel Execution:** Steps without dependencies run concurrently to speed up workflows.
- **Auto-install:** Prompts the user to install missing tools on the fly.
- **Self-correction:** Automatically strips unrecognized flags and retries commands.

```python
executor = RegistryExecutor(registry=ToolRegistry(), max_workers=5)
result = await executor.execute_plan(plan)
```

### 🤖 AutonomousExecutor (`siyarix/executor_autonomous.py`)
Built for raw power, this executor runs shell commands generated by the LLM, complete with live streaming output.

- **Live Streaming:** Rich, real-time terminal output for every command.
- **Stealth Integration:** Injects random execution delays when the `StealthEngine` is active to evade detection.
- **Sudo Caching:** Pre-fetches sudo passwords before the live display begins to prevent visual stuttering.
- **Parser Integration:** Automatically routes raw terminal output into structured tool parsers.

```python
executor = AutonomousExecutor(
    max_workers=10,
    command_review=True,
    registry=tool_registry
)
result = await executor.execute_plan(plan, live_display=True)
```

### 🗺️ Mode-to-Executor Mapping
How `AgentCore.execute_goal()` decides which executor to use:

| Mode | Executor | Description |
|------|----------|-------------|
| **REGISTRY** | `RegistryExecutor` | Safer, heuristic planning based on registered tools. |
| **AUTONOMOUS** | `AutonomousExecutor` | Dynamic LLM planning executing raw shell commands. |
| **HYBRID** | Both (Fallback) | Tries autonomous first; falls back to the registry if it fails. |
| **INTERACTIVE** | `RegistryExecutor` (w/ Approval) | Previews the plan and waits for user confirmation. |

---

## 🔗 Dependency Resolution

Steps aren't just run blindly; they are organized into dependency layers using `ExecutionPlan.get_ready_steps()`.

```text
Layer 0: [recon_scan, dns_enum]          # No dependencies (Runs first)
Layer 1: [nuclei_scan, nikto_scan]        # Depends on Layer 0
Layer 2: [metasploit_exploit]             # Depends on Layer 1
```

> [!NOTE]
> Steps within the same layer execute concurrently via the `AsyncWorkerPool`. However, cross-layer dependencies strictly enforce sequential execution to ensure prerequisites are met.

---

## ⚡ AsyncWorkerPool

Siyarix handles concurrency gracefully using bounded async workers and semaphores.

```python
pool = AsyncWorkerPool(max_workers=5, max_queue=100)
result = await pool.submit(coro_func, *args)
await pool.close(timeout=30.0)
```
- **Backpressure control:** Keeps memory and CPU usage in check.
- **Graceful shutdown:** Cancels tasks safely when the system stops.
- **Auto-cleanup:** Tracks tasks and cleans up via done callbacks.

---

## 🔍 Output Parsing

Raw output isn't very useful to an AI. Siyarix routes raw tool output through specialized parsers to extract structured data.

```python
parser_registry = ParserRegistry()
parser_registry.discover()
parser_registry.parse(tool, output)
```

**Examples of extracted findings:**
- 🔌 **Port Scanners:** Ports, protocols, service versions, banners.
- 🐛 **Vuln Scanners:** CVE IDs, severity levels, CVSS vectors.
- 🌐 **Web Scanners:** URLs, tech stacks, exposed directories.

> [!IMPORTANT]
> Once parsed, findings are immediately inserted into the **KnowledgeGraph**, empowering the LLM to make better downstream decisions.

---

## 🩹 Error Recovery

Things go wrong. The `Validator` class (`siyarix/validators.py`) ensures the engine can recover intelligently from failures.

### 🔄 Recovery Actions

| Action | Description |
|--------|-------------|
| `RETRY` | Try again with a modified step (e.g., adding a `-Pn` flag). |
| `RETRY_ALTERNATIVE`| Swap the tool entirely (e.g., fallback from Nuclei to Nikto). |
| `SKIP` | Abandon the step and move on. |
| `ESCALATE` | Pause and ask the user what to do. |

### 🛠️ Specific Recovery Patterns

| Scenario | Detection | Action |
|----------|-----------|--------|
| **Nmap filtered ports** | Output contains "filtered" | Retry with `-Pn` flag. |
| **Web scanner refused** | Error contains "refused" | Swap tool (Nikto ↔ Nuclei). |
| **Exhausted retries** | `retry_count >= max_retries` | Skip step entirely. |

---

## ⛓️ CommandPipeline

The `CommandPipeline` (`siyarix/core/pipeline.py`) allows for natural language command chaining:

```text
scan 10.0.0.1 then nmap -sV 10.0.0.1
scan 10.0.0.1 and then enumerate services
```
It supports natural separators like `|`, `then`, `and then`, and `followed by`. Previous step outputs are automatically passed forward as context.

---

## 📊 EngineResult

When execution finishes, it returns a comprehensive `EngineResult` summarizing everything that happened.

```python
@dataclass
class EngineResult:
    success: bool = False
    summary: str = ""
    all_findings: list[dict] = field(default_factory=list)
    step_results: list[Any] = field(default_factory=list)
    raw_output: str = ""
    duration_ms: float = 0.0
    retries_performed: int = 0
    plan_id: str = ""
    error_message: str = ""
```

---

## 🌊 Multi-Wave Execution

For deep, autonomous operations, the `AgentCore` can execute goals in "waves."

```python
result = await agent.execute_multi_wave(goal, max_waves=5)
```

**How it works:**
1. Executes the goal using current context.
2. Collects new findings.
3. Feeds those findings back in as context for the next wave.
4. Naturally stops when no new findings are discovered.

---

## 💸 Session Budgeting

In addition to per-plan limits, Siyarix enforces session-level limits to prevent runaway LLM costs.

| Limit | Default | Environment Variable |
|-------|---------|---------------------|
| **Max tokens** | 100,000 | `SIYARIX_MAX_TOKENS` |
| **Max cost** | $2.00 | `SIYARIX_MAX_COST_USD` |

---

## 🔌 Integration Points

The Execution Engine doesn't work in isolation. It hooks into the entire Siyarix ecosystem:

| Component | Integration Role |
|-----------|------------------|
| **PermissionGate** | Evaluates steps for BLOCK/REVIEW/ALLOW states pre-execution. |
| **DLP Engine** | Scrubs results for sensitive data post-execution. |
| **KnowledgeGraph** | Receives structured findings in real-time. |
| **AuditLogger** | Records every execution with a cryptographic SHA-256 chain. |
| **StealthEngine** | Requests random delay injections for covert operations. |
| **MetricsCollector** | Tracks duration, success rates, and error frequencies. |
| **Continuous Learning**| Observes execution outcomes to improve future planning. |
