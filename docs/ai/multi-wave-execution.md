# Multi-Wave Execution & Live Streaming

Siyarix uses a multi-wave execution loop that enables iterative, LLM-driven workflows. Instead of running a single batch of commands and stopping, the system can execute multiple waves, analyse results between waves, and decide whether to continue with deeper commands.

## Execution flow

```
User request → LLM plans commands → Wave 1 executes → 
  LLM analyses results → Wave 2 (if needed) → ... → 
  Final response
```

## Multi-wave loop

### How it works

1. The LLM analyses the user's request and produces a plan with one or more shell commands
2. All commands in the plan run in parallel
3. After completion, the LLM receives the outputs and analyses them
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

### When the LLM requests another wave

The LLM receives the original request plus all outputs from completed waves and decides:

- **`needs_tools=false`**: Present the final response to the user
- **`needs_tools=true`**: Generate a new plan for the next wave (e.g., found open ports, now scan for vulnerabilities)

## Live streaming output

During execution, command output is streamed line-by-line in real time using a Rich Live display.

### Display behavior

- A single `Live` Panel shows the output of the currently focused command
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

### Streaming output capture

Each command's stdout and stderr is captured line-by-line via `safe_run_async_stream`:

```python
result = await safe_run_async_stream(
    ["sh", "-c", command],
    timeout=agent_timeout,
    validate=False,
    on_stdout=lambda line: state.lines.append(line),
    on_stderr=lambda line: state.lines.append(line),
)
```

The last 200 lines of each command's output are kept in memory for display.

## Command review

Before any execution begins, each shell command can be reviewed interactively.

### Review prompt

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

Options:

| Choice | Effect |
|--------|--------|
| `run` | Execute the command as-is |
| `edit` | Edit the command before execution |
| `step` | Execute but step through one at a time |
| `cancel` | Skip/cancel this command |

### Toggle review

The review prompt can be toggled on and off during a session:

```
/command off    # Skip review, run all commands immediately
/command on     # Show review prompt before each command
```

The current state is shown with `/command` alone.

### Review timing

Commands are reviewed **before** the Live display starts, in a synchronous phase. This ensures the review panel is shown cleanly without terminal output conflicts. Once all commands are approved, execution begins with the Live display.

## Wave summary

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
