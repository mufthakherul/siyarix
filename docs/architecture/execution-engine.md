# Execution Engine

The execution subsystem transforms `ExecutionPlan` objects into executed commands. It is built on a layered architecture with a shared **BaseExecutor** providing budget tracking, guardrails, DLP integration, and permission gating for all specialized executors.

---

## Architecture

```
ExecutionPlan (from Planner)
         │
         ▼
┌───────────────────────────────────────────────────────────┐
│                   BaseExecutor                             │
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

## Plan Structure

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

### PlanStep

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

## Shared Infrastructure (BaseExecutor)

The `BaseExecutor` in `siyarix/executor.py` provides common functionality shared by all executor variants:

### ExecutionBudget

Tracks and enforces resource consumption limits:

| Limit | Default | Description |
|-------|---------|-------------|
| `max_iterations` | 50 | Maximum planning/execution iterations |
| `max_tool_calls` | 100 | Maximum tool invocations |
| `max_duration_s` | 600 | Maximum wall-clock execution time |

The budget is checked before every step, and exhaustion flags prevent further execution.

### ToolCallTracker

Records tool-call outcomes and enforces guardrail policies:

| Guardrail | Threshold | Action |
|-----------|-----------|--------|
| Exact failure warn | 2 failures | Warning logged |
| Exact failure block | 5 failures | Tool blocked |
| Same-tool failure halt | 8 consecutive | Tool halted |
| No-progress block | 5 calls with same args | Blocked |

Failure state persists to `tool_failures.json` for continuity across sessions.

### Permission Gate Integration

Every step can be checked against the `PermissionGate` before execution. The flow is:

1. Check if command is blocked → raise `PermissionDeniedError`
2. If review required → invoke `review_and_confirm()` for user approval
3. User can approve, modify, or cancel the command

### DLP Redaction

After execution, results are passed through the `DLPEngine` to redact sensitive values before they enter the KnowledgeGraph or session log.

---

## Executor Types

Siyarix provides two main executor implementations, with mode dispatching handled by the `AgentCore`:

### RegistryExecutor (`siyarix/executor_registry.py`)

Executes plan steps through the `ToolRegistry` with full guardrails and DAG support.

| Feature | Description |
|---------|-------------|
| **Tool dispatch** | Executes via ToolRegistry capability lookup |
| **Parallel execution** | Steps without dependencies run concurrently via AsyncWorkerPool |
| **DAG workflows** | Delegates to WorkflowEngine for DAG-based plans |
| **Auto-install** | Prompts user to install missing tools at runtime |
| **Alternative fallback** | Falls back through TOOL_ALTERNATIVES on tool failure |
| **Self-correction** | Strips unrecognized flags and retries |
| **Custom executors** | Register per-tool handlers via `register_executor()` |

```python
executor = RegistryExecutor(registry=ToolRegistry(), max_workers=5)
result = await executor.execute_plan(plan)
```

### AutonomousExecutor (`siyarix/executor_autonomous.py`)

Executes raw shell commands generated by the LLM with live streaming output.

| Feature | Description |
|---------|-------------|
| **Shell command execution** | Executes via platform subprocess with timeout |
| **Live streaming** | Rich live display showing real-time output per command |
| **Command review** | Pre-execution user confirmation for all shell commands |
| **Stealth integration** | Random delay injection when StealthEngine is active |
| **Sudo password pre-fetch** | Caches sudo passwords before live display starts |
| **Auto-install prompt** | Detects missing tools (exit code 126/127) and offers install |
| **Parser integration** | Routes output through tool-specific parsers |
| **Custom tool handlers** | Register handlers for non-command tool steps |

```python
executor = AutonomousExecutor(
    max_workers=10,
    command_review=True,
    registry=tool_registry
)
result = await executor.execute_plan(plan, live_display=True)
```

### Mode-to-Executor Mapping

The `AgentCore.execute_goal()` in `siyarix/core/__init__.py` dispatches based on mode:

| Mode | Method | Executor | Description |
|------|--------|----------|-------------|
| **REGISTRY** | `_execute_registry()` | RegistryExecutor | Heuristic planning, tool-based execution |
| **AUTONOMOUS** | `_execute_autonomous()` | AutonomousExecutor | LLM planning, shell command execution |
| **HYBRID** | `_execute_hybrid()` | Autonomous → Registry fallback | Tries autonomous first, falls back to registry |
| **INTERACTIVE** | `_execute_interactive()` | RegistryExecutor with user approval | Plan preview + user confirmation |

---

## Dependency Resolution

Steps are organized into dependency layers using the `get_ready_steps()` method on `ExecutionPlan`:

```
Layer 0: [recon_scan, dns_enum]          # No dependencies
Layer 1: [nuclei_scan, nikto_scan]        # Depends on recon_scan
Layer 2: [metasploit_exploit]             # Depends on nuclei + nikto
```

Steps within the same layer execute concurrently via `AsyncWorkerPool.submit()`.
Cross-layer dependencies enforce sequential execution.

---

## AsyncWorkerPool

Bounded async concurrency via semaphore:

```python
pool = AsyncWorkerPool(max_workers=5, max_queue=100)
result = await pool.submit(coro_func, *args)
await pool.close(timeout=30.0)
```

- Configurable max concurrent workers
- Backpressure via bounded queue semaphore
- Graceful task cancellation on shutdown
- Task tracking with auto-cleanup via done callbacks

---

## Output Parsing

Tool output is routed through tool-specific parsers:

```python
parser_registry = ParserRegistry()
parser_registry.discover()
parser_registry.parse(tool, output)
```

Each parser extracts structured findings:
- **Port Scanners**: ports, protocols, service versions, banners
- **Vuln Scanners**: vulnerability IDs, severity, CVSS vectors, descriptions
- **Web Scanners**: URLs, technologies, directories, forms
- **Recon Tools**: subdomains, DNS records, WHOIS data

Findings are immediately inserted into the **KnowledgeGraph** for downstream reasoning.

---

## Error Recovery

The `Validator` class in `siyarix/validators.py` implements plan validation and step-level recovery:

### RecoveryAction Enum

| Action | Description |
|--------|-------------|
| `RETRY` | Retry with modified step (e.g., adding `-Pn` flag) |
| `RETRY_ALTERNATIVE` | Try alternative tool (e.g., nuclei → nikto) |
| `SKIP` | Skip step entirely |
| `ABORT` | Abort entire plan |
| `ESCALATE` | Escalate to user decision |
| `DEGRADE` | Continue with degraded functionality |

### Specific Recovery Patterns

| Scenario | Detection | Action |
|----------|-----------|--------|
| Nmap filtered ports | Error contains "filtered" | Retry with `-Pn` flag |
| Web scanner refused | Error contains "refused" | Swap tool (nikto ↔ nuclei) |
| Directory brute 404s | Error contains "404" | Add more file extensions |
| Generic transient | `step.can_retry` | Simple retry with increment |
| Exhausted retries | `retry_count >= max_retries` | Skip step |

### Validation Pipeline

```python
validator = Validator()
results = await validator.validate_plan(plan.steps)
recovery = await validator.plan_recovery(failed_step, error)
```

---

## CommandPipeline

The `CommandPipeline` in `siyarix/core/pipeline.py` parses chained instructions:

```
scan 10.0.0.1 then nmap -sV 10.0.0.1
scan 10.0.0.1 and then enumerate services
```

Supports pipe (`|`), "then", "and then", "followed by" separators. Each step is executed sequentially with previous output passed as context.

---

## EngineResult

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

## Multi-Wave Execution

The `AgentCore` supports multi-wave execution for autonomous mode:

```python
result = await agent.execute_multi_wave(goal, max_waves=5)
```

Each wave:
1. Executes the goal with context from previous waves
2. Collects findings
3. Feeds findings as context for the next wave
4. Stops when no new findings are discovered

---

## Budget Checking

The `_check_budget()` method enforces session-level limits:

| Limit | Default | Environment Variable |
|-------|---------|---------------------|
| Max tokens per session | 100,000 | `SIYARIX_MAX_TOKENS` |
| Max cost per session | $2.00 | `SIYARIX_MAX_COST_USD` |

---

## Integration Points

| Component | Integration |
|-----------|------------|
| **PermissionGate** | Pre-execution BLOCK/REVIEW/ALLOW per step |
| **DLP Engine** | Post-execution data leak inspection on results |
| **KnowledgeGraph** | Findings inserted in real-time |
| **AuditLogger** | Every execution logged with SHA-256 chain |
| **EventBus** | Events emitted per step lifecycle |
| **MetricsCollector** | Execution duration, success rate, error rate |
| **CacheManager** | Cached tool outputs (LRU + TTL) |
| **OfflineStore** | Results persisted for offline retrieval |
| **Validator** | Plan validation and step recovery |
| **StealthEngine** | Random delay injection for covert ops |
| **Continuous Learning System** | Observes execution for skill learning |
