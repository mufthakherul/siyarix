# Multi-Wave Execution & Live Streaming

Siyarix uses a multi-wave execution loop that enables iterative, LLM-driven workflows. Rather than executing a single batch of commands, the system runs multiple waves — each wave's results are analysed by the LLM to determine the next set of commands — enabling autonomous multi-step security operations.

---

## Execution Flow

```
User request → LLM plans commands → Wave 1 executes →
  LLM analyses results → Wave 2 (if needed) → ... →
  Final response (up to 5 waves)
```

---

## Multi-Wave Loop

### How It Works

1. The LLM analyses the user's request and produces a JSON plan with shell commands
2. All commands in the plan run **in parallel** within the wave
3. After completion, the LLM receives all outputs and analyses them
4. If more work is needed (missing data, tool not found, deeper recon required), the LLM generates a new plan for the next wave
5. This repeats for up to **5 waves**

```python
max_waves = 5
for wave in range(max_waves):
    if not plan or not plan.steps:
        break
    # Execute all steps in parallel
    raw_results = await execute_wave(plan.steps)
    # Ask LLM: are we done?
    plan = await llm.analyse_and_plan(wave_results)
```

### Wave Decision

The LLM receives the original request plus all outputs from completed waves and responds with:

- **`needs_tools=false`**: Present the final response to the user (done)
- **`needs_tools=true`**: Generate a new plan for the next wave (e.g., found open ports → now scan for vulnerabilities)

### Parallel Execution Within Waves

All steps in a single wave execute concurrently:

```python
async def execute_wave(steps: list[dict]) -> list[dict]:
    tasks = [execute_step(step) for step in steps]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [format_result(r, step) for r, step in zip(results, steps)]
```

---

## Live Streaming Output

During execution, command output is streamed line-by-line in real time using a Rich `Live` display.

### Display Behavior

- A single `Live` Panel shows output of the currently focused command
- The display auto-cycles through running commands as they complete
- Each panel has a coloured border indicating status:
  - **Cyan**: Still running
  - **Green**: Completed successfully (exit code 0)
  - **Red**: Failed (non-zero exit code)
- The panel title shows the command and a status icon (`·` running, `✓` success, `✗` failure)

```python
with Live(console=console, refresh_per_second=10, screen=False) as live:
    while not done_set:
        await asyncio.sleep(0.1)
        # Auto-cycle to next unfinished command
        if cmd_states[focus_idx].done:
            unfinished = [i for i, st in enumerate(cmd_states) if not st.done]
            if unfinished:
                focus_idx = unfinished[0]
            else:
                done_set = True
        live.update(RichPanel(...))
```

### Streaming Output Capture

Each command's stdout and stderr is captured line-by-line via `safe_run_async_stream`:

```python
result = await safe_run_async_stream(
    command,
    timeout=agent_timeout,
    validate=False,
    on_stdout=lambda line: state.lines.append(line),
    on_stderr=lambda line: state.lines.append(line),
)
```

The last 200 lines of each command's output are retained in memory for display.

---

## Command Review

Before execution begins, each shell command can be reviewed interactively via the permission gate.

### Review Prompt

When command review is enabled (default: on), each command shows a review panel:

```
╭──────────────── Command Execution Review ─────────────────╮
│ Tool: raw                                                 │
│ Reason: Raw shell command from LLM plan                   │
│                                                           │
│ nmap -sS -sV -O -Pn example.com                           │
╰───────────────────────────────────────────────────────────╯
Review command [edit/run/step/cancel] (run):
```

| Choice | Effect |
|--------|--------|
| `run` | Execute the command as-is |
| `edit` | Edit the command before execution |
| `step` | Execute but step through one at a time |
| `cancel` | Skip/cancel this command |

### Toggle Review

```bash
/command off    # Skip review, run all commands immediately
/command on     # Show review prompt before each command
```

The current state is shown with `/command` alone.

### Review Timing

Commands are reviewed **before** the Live display starts, in a synchronous phase. Once all commands are approved, execution begins with the Live display.

---

## Wave Summary

After each wave completes, a summary panel is shown for each command:

```
╭─ ✓ $ nmap -sS -sV -O -Pn example.com ───────────────────╮
│ PORT     STATE  SERVICE    VERSION                       │
│ 22/tcp   open   ssh        OpenSSH 8.9p1                 │
│ 80/tcp   open   http       nginx 1.24.0                  │
│ 443/tcp  open   https      nginx 1.24.0                  │
╰──────────────────────────────────────────────────────────╯
```

Each wave's output is fed back to the LLM to inform the next wave's plan.

---

## Event Streaming

The `AssistantMessageEventStream` provides granular, event-driven output for streaming scenarios:

- **Text tokens**: Incremental LLM response content
- **Tool calls**: Structured function call objects
- **Error events**: Provider errors with classification
- **Wave boundaries**: Start/end markers for each execution wave

---

## Safety Integration

Each command in every wave passes through the full safety pipeline:

1. **DangerAnalysis** — `DangerAnalyzer` classifies command destructiveness
2. **InputValidation** — `InputValidator` rejects injection patterns
3. **SecretRedaction** — `SecretRedactor` strips credentials from output
4. **Permission Gate** — Interactive review before execution

---

## Related Modules

| Module | Path | Purpose |
|--------|------|---------|
| `LLMEngineMixin._execute_instruction` | `src/siyarix/chat/engine.py:57` | Multi-wave execution orchestrator |
| `LLMEngineMixin._execute_agent` | `src/siyarix/chat/engine.py` | Agent loop with LLM-driven wave planning |
| `AssistantMessageEventStream` | `src/siyarix/events.py` | Granular event streaming for UI |
| `safe_run_async_stream` | `src/siyarix/subprocess_utils.py` | Async subprocess with line-by-line streaming |
| `DangerAnalyzer` | `src/siyarix/security_hardening.py` | Pre-execution command danger classification |
