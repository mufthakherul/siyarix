# AI Agent Pipeline

The AI agent pipeline processes user input through a structured lifecycle of **Plan → Execute → Observe-Reason-Act**, orchestrated by the `AgentCore`. The pipeline supports four operational modes and an autonomous **Observe-Reason-Act** loop for goal-driven operation, with budget checking and multi-wave execution.

---

## Agent Lifecycle

```
                     ┌──────────────────┐
                     │   User Input     │
                     └────────┬─────────┘
                              ▼
                     ┌──────────────────┐
                     │  IntentRouter    │
                     │  (keyword:       │
                     │   scan/recon/web │
                     │   /brute/exploit)│
                     └────────┬─────────┘
                              ▼
                     ┌──────────────────┐
                     │  Context Manager │
                     │  (build/compress  │
                     │   context window) │
                     └────────┬─────────┘
                              ▼
                     ┌──────────────────┐
          ┌──────────│  Planner Router  │──────────┐
          ▼          └──────────────────┘          ▼
   ┌─────────────┐                       ┌─────────────────┐
   │ Registry    │                       │ Autonomous      │
   │ Planner     │                       │ Planner (LLM)   │
   │ (heuristic) │                       │ (dynamic)       │
   └──────┬──────┘                       └────────┬────────┘
          │                                       │
          └──────────────┬────────────────────────┘
                         ▼
                ┌──────────────────┐
                │  PermissionGate  │──→ DLP Engine
                │  (BLOCK/REVIEW/  │
                │   ALLOW)         │
                │  + DLP redaction │
                └────────┬─────────┘
                         ▼
                ┌──────────────────┐
                │  ExecutionEngine │
                │  (plan → steps)  │
                │  Validator       │
                │  (recovery)      │
                └────────┬─────────┘
                         ▼
                ┌──────────────────┐
                │  Observe-Reason- │
                │  Act Loop        │
                │  (autonomous)    │
                │  + Budget Check  │
                │  + Multi-Wave    │
                └──────────────────┘
```

---

## Stage 1: Intent Routing

The `IntentRouter` classifies input through keyword matching:

| Keyword | Mode | Risk Tier | Latency |
|---------|------|-----------|---------|
| scan, nmap, port scan | scan | MEDIUM | ~0ms |
| recon, enumerate, discover | recon | LOW | ~0ms |
| web, http, nikto, nuclei | web | MEDIUM | ~0ms |
| brute, crack, password | brute | HIGH | ~0ms |
| exploit, metasploit, attack | exploit | HIGH | ~0ms |

Produces an `IntentRoute` with:
- `mode`: scan / recon / web / brute / exploit / general
- `risk_tier`: LOW / MEDIUM / HIGH
- `requires_confirmation`: Boolean

---

## Stage 2: Context Building

The **Context Manager** constructs the LLM context window:

- Conversation history (deque, max 300 per session)
- Knowledge Graph entity summaries
- Current operational phase
- Tool availability from ToolRegistry
- Session metadata (target, mode, findings)
- **CompactionEngine** optimizes context for LLM token limits (`analyze_tokens`, `compress_context`)

Output: A compressed, structured context passed to the planner.

---

## Stage 3: Planning

### Planner Router

Selects the planning strategy based on mode:

```python
if mode == "registry" or mode == "offline":
    plan = planner_registry.plan(goal, available_tools)
elif mode == "autonomous":
    plan = await autonomous_planner.plan(goal, llm_call, ...)
else:  # integrated (default)
    plan = await planner.plan(goal, mode="integrated", ...)
```

### RegistryPlanner (Heuristic)

- Uses keyword index to map intents → plan templates
- 500+ multi-word intent patterns for tool selection
- Tool alternative chains for graceful degradation
- Deterministic, no AI dependency
- Always available as fallback in offline/air-gapped environments

### AutonomousPlanner (LLM-Driven)

- Receives intent + compressed context + tool schemas
- Returns structured `ExecutionPlan` with tool names, ordering, arguments
- Driven by configured AI provider via the ProviderManager
- Supports ToolCallRepair for malformed LLM output

---

## Stage 4: Permission Gating & DLP

Every planned step passes through the permission gate:

1. **Syntax Validation**: Length limits, null bytes, shell injection patterns, target format
2. **Danger Analysis**: 38+ signatures for destructive/recon/exploit patterns
3. **DLP Inspection**: Data leak prevention pattern detection (24+ signatures)

Returns one of:
- `ALLOW` — proceeds without input
- `REVIEW` — requires user confirmation
- `BLOCK` — permanently denied and logged

The PermissionGate and DLP Engine work together as a combined security layer rather than sequential separate stages.

---

## Stage 5: Execution

The execution subsystem transforms plans into executed commands:

1. **BaseExecutor** validates plan structure and budget
2. **Validator** checks step integrity (tool presence, arguments, timeout)
3. **AsyncWorkerPool** dispatches steps with bounded concurrency
4. **Route** output through tool-specific parsers
5. **Extract** findings into KnowledgeGraph
6. **Handle** errors with recovery actions (RETRY, RETRY_ALTERNATIVE, SKIP, ABORT)

Two main executor types based on mode:

| Executor | Mode | Behavior |
|----------|------|----------|
| `RegistryExecutor` | REGISTRY | Deterministic, template-driven, no AI |
| `AutonomousExecutor` | AUTONOMOUS | Full autonomy, loop until objective met |

---

## Stage 6: Observe-Reason-Act Loop (Autonomous Mode)

For `AUTONOMOUS` mode, the system runs an autonomous loop:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Observe    │────▶│    Reason    │────▶│     Act      │
│              │     │              │     │              │
│ • Tool output│     │ • Analyze    │     │ • Execute    │
│ • Env state  │     │ • Update KG  │     │   commands   │
│ • Scan res.  │     │ • Select     │     │ • Run tools  │
│ • Errors     │     │   next action│     │ • Invoke     │
│              │     │ • Check      │     │   sub-agents │
│              │     │   completion │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
        ▲                                         │
        └─────────────────────────────────────────┘
                     (feedback loop)
```

**Observe**: Collect environment state, tool outputs, scan results, errors
**Reason**: Analyze findings, update KnowledgeGraph, select next action via LLM
**Act**: Execute selected commands, run tools, invoke sub-agents via Swarm

Reflection is integrated within the Observe-Reason-Act loop rather than being a separate stage.

Loop terminates when:
- Objective is achieved (verified by LLM)
- Max iteration limit is reached (default: 10 iterations)
- Budget is exhausted (token or cost limit)
- User interrupts with Ctrl+C
- Safety gate blocks critical action

---

## Multi-Wave Execution

The `AgentCore.execute_multi_wave()` method enables progressive execution:

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

```python
async def _check_budget(self):
    record = self._usage_tracker.session_totals()
    if record.total_tokens >= self._max_tokens_per_session:
        raise BudgetExceededError("Session token limit reached.")
    if record.estimated_cost_usd >= self._max_cost_usd:
        raise BudgetExceededError("Session cost limit reached.")
```

| Limit | Default | Environment Variable |
|-------|---------|---------------------|
| Max tokens per session | 100,000 | `SIYARIX_MAX_TOKENS` |
| Max cost per session | $2.00 | `SIYARIX_MAX_COST_USD` |

---

## Streaming Event System

During execution, all pipeline stages emit events through the **EventBus**:

```
EventBus topic types (from EventType enum):
  AGENT_START          → Agent started
  PLAN_CREATED         → ExecutionPlan created
  PLAN_STEP_START      → Step execution begins
  PLAN_STEP_COMPLETE   → Step completed successfully
  PLAN_STEP_FAILED     → Step failed
  PLAN_COMPLETE        → Plan completed (success or failure)
  AGENT_COMPLETE       → Agent execution complete
  VALIDATION_FAILED    → Step validation failed
  CUSTOM               → Custom/sub-type events
```

---

## Autonomous Agent Loop Configuration

```python
# Default configuration (AgentCore level)
max_iterations = 10             # CLI agent default
max_tokens_per_session = 100000
max_cost_usd = 2.00
safety_mode = "strict"           # strict | permissive (via SIYARIX_SAFE_MODE env)
```

---

## Output & Results

After execution, the pipeline produces:

| Output | Destination | Format |
|--------|-------------|--------|
| Findings | KnowledgeGraph | In-memory directed graph |
| Report | ReportEngine | MARKDOWN, HTML, JSON + CVSS |
| Audit Trail | AuditLogger | Tamper-evident SHA-256 chain |
| Session Log | ChatSession | JSONL tree format |
| Metrics | MetricsCollector | Execution metrics |
| Offline Backup | OfflineStore | SQLite WAL mode |
| Learned Skills | Continuous Learning System | SQLite + anonymized patterns |
