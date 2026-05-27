# AI Agent Pipeline

The AI agent pipeline processes user input through a series of stages, from intent detection to result presentation.

## Pipeline stages

### 1. Input reception

User input arrives through one of three channels:

- **CLI command**: `siyarix scan 10.0.0.1`
- **Chat message**: typed in the interactive REPL
- **Pipe/batch**: stdin or batch file

### 2. Intent routing

The `IntentRouter` classifies input using four stages:

1. **Exact match**: Check against registered command patterns
2. **Regex match**: Pattern-match against known intent signatures
3. **Keyword match**: Extract intent from keywords (scan, exploit, report, etc.)
4. **LLM fallback**: If all else fails, ask the AI provider to classify

The router produces an `IntentRoute` with intent type, risk tier, and extracted parameters.

### 3. Task planning

The `TaskPlanner` converts the intent into an execution plan:

```
Intent + Target → TaskPlanner → ExecutionPlan
```

Each `ExecutionPlan` contains:

- **Target**: The target host, network, or URL
- **Steps**: Ordered list of tools to run
- **Dependencies**: Step ordering (step B depends on step A's output)
- **Mode**: Registry (deterministic) or Autonomous (AI-driven)

The planner tries AI providers in order of preference. If all fail, the `RuleInterpreter` provides heuristic fallback.

### 4. Permission gating

Every step passes through the three-stage gate:

1. **Syntax validation**: Is the command well-formed?
2. **Danger analysis**: Does it match dangerous patterns (rm -rf, dd, format)?
3. **Persona ACL**: Does the active persona permit this tool?

Gates return: `ALLOW`, `DENY`, or `FLAG` (requires user confirmation).

### 5. Execution

The `ExecutionEngine` runs the plan:

- Steps execute in dependency order
- Independent steps run in parallel via `asyncio.gather()`
- Output is routed through the appropriate parser
- Findings are extracted and stored in the knowledge graph
- Errors trigger exponential backoff with jitter

### 6. Result aggregation

Results are:

- Displayed to the user (table, JSON, YAML, or CSV)
- Logged to the session log and audit trail
- Stored in the offline store for later retrieval
- Added to the knowledge graph for downstream reasoning

## Observe-Reason-Act loop

For autonomous agent mode (`siyarix agent "..."`), the system uses an Observe-Reason-Act loop:

```
┌─────────┐    ┌─────────┐    ┌─────────┐
│ Observe │───▶│ Reason  │───▶│   Act   │
└─────────┘    └─────────┘    └─────────┘
     ▲                            │
     └────────────────────────────┘
          (feedback loop)
```

- **Observe**: Collect environment state, tool outputs, scan results
- **Reason**: Analyze findings, update knowledge graph, select next action
- **Act**: Execute selected commands, run tools

The loop continues until the objective is achieved or the max iteration limit is reached.

## Multi-agent coordination

For complex objectives, the `CoordinatorAgent`:

1. Decomposes the goal into sub-tasks
2. Creates role-specific agents (recon, scanner, enumerator, exploiter, reporter)
3. Assigns tasks based on agent role
4. Executes with `asyncio.gather()` for parallel work
5. Broadcasts findings across the team
6. Synthesizes results into a final report

## Execution modes

| Mode | Planning | Permission | Autonomy |
|------|----------|------------|----------|
| `integrated` | AI-assisted | Full gate | User confirms flagged commands |
| `registry` | Tool metadata (deterministic) | Full gate | No AI required |
| `autonomous` | AI-driven | Minimal | No user confirmation needed |
