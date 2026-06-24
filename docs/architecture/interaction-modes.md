# Interaction Modes

Siyarix supports four interaction modes — **REGISTRY**, **AUTONOMOUS**, **HYBRID**, and **INTERACTIVE** — across two primary interfaces: the **CLI** (command-line interface with subcommands) and the **REPL** (interactive conversational shell). Mode selection happens at invocation time and can be overridden via the `REPL` prompt with natural language commands.

---

## Mode Selection

### CLI Mode

When invoked from the command line, mode is selected by the `main_callback()` in `cli/main.py`:

```bash
# Registry mode (default): execute a single command from template registry
siyarix scan 10.0.0.1
siyarix recon example.com

# Autonomous mode: goal-driven autonomous operation
siyarix --mode autonomous "Enumerate all services on 10.0.0.0/24"

# Interactive (REPL) mode: conversational shell
siyarix --interactive
# or
siyarix -i

# Batch mode: process commands from stdin or file
siyarix --batch commands.txt

# Version info
siyarix --version

# Help
siyarix --help
```

### REPL Mode Mode Switching

Within the REPL, users can switch modes via natural language:

```
╭─ Siyarix v2.0.0 ─ INTERACTIVE ───────────────────────────╮
│                                                           │
│  ℹ Type 'help' for commands, 'exit' to quit.            │
│  ℹ Use '/mode <mode>' or say: 'switch to autonomous'     │
│                                                           │
╰───────────────────────────────────────────────────────────╯

> switch to autonomous mode
  ✓ Mode set to AUTONOMOUS — I'll now operate autonomously.

> what mode am i in?
  You're in AUTONOMOUS mode.
```

---

## Mode Comparison

| Aspect | REGISTRY | AUTONOMOUS | HYBRID | INTERACTIVE |
|--------|----------|------------|--------|-------------|
| **AI Required** | No | Yes | Yes | Yes |
| **User Approval** | No | No | No | Yes (every step) |
| **Planning** | Heuristic templates | LLM-driven | LLM + registry | Registry + approval |
| **Execution** | Deterministic | Full loop | Auto + guided | Step-by-step |
| **Best for** | Known operations | Reconnaissance | Complex goals | Teaching/audit |
| **Speed** | Fastest | Fast | Moderate | Slowest |
| **Risk** | Low | Medium | Medium | Lowest |
| **Autonomy Level** | None | High | Medium | None |

---

## 1. REGISTRY Mode

Executes commands using predefined plan templates from the tool registry with no AI involvement.

### Characteristics

- **No AI dependency**: Functions in air-gapped, offline, or degraded environments
- **Deterministic**: Same input always produces same plan
- **Fast**: No LLM latency, instant execution
- **Safe**: No hallucination, no unexpected behavior

### Flow

```
Input (scan 10.0.0.1)
  → IntentRouter classifies: scan
  → RegistryPlanner matches: "scan" → ["nmap -sV 10.0.0.1", "nmap -sC 10.0.0.1"]
  → PermissionGate validates
  → RegistryExecutor executes
  → Output parsed, findings stored in KnowledgeGraph
```

### Tool Hierarchy (RegistryPlanner)

Templates are organized with primary tools and alternatives:

```
scan:
  primary: nmap
  alternatives: [masscan, rustscan]
  commands:
    - nmap -sV {target} -oX {output}
    - nmap -sC {target} -oX {output}
```

---

## 2. AUTONOMOUS Mode

Full autonomy mode where the AI plans and executes toward a goal with no per-step user confirmation.

### Characteristics

- **Goal-driven**: Set a goal, let the agent work toward it
- **LLM-driven planning**: Dynamic plans adapted to environment feedback
- **Observe-Reason-Act loop**: Continuous feedback loop with integrated reflection
- **Budget enforcement**: Token and cost limits applied per session
- **Multi-wave execution**: Progressive refinement across execution waves

### Flow

```
Input ("Enumerate 10.0.0.1")
  → IntentRouter classifies
  → Context Manager builds context
  → AutonomousPlanner generates ExecutionPlan
  → PermissionGate + DLP validates
  → AutonomousExecutor executes with ORA loop
  → Loop until: objective met / max_iterations (10) / budget / user interrupt
  → Final summary and report
```

### Autonomous Loop

```
Iteration 1: nmap -sV 10.0.0.1 → ports 22,80,443 open
  → Observe: Apache 2.4.41 on port 80
  → Reason: Apache version is outdated, known CVEs
  → Act: nikto -h 10.0.0.1:80

Iteration 2: nikto finds /phpmyadmin, /wp-admin
  → Observe: phpMyAdmin detected, WordPress found
  → Reason: phpMyAdmin is high-risk, WordPress version unknown
  → Act: curl /wp-json to get version

Iteration 3: Determine WordPress 5.6.2
  → Observe: Version known
  → Reason: 5.6.2 has known RCE CVEs (CVE-2021-29447, etc.)
  → Act: Check if target is in-scope for exploitation
  → Objective achieved: Fully enumerated. Report generated.
```

---

## 3. HYBRID Mode

A balanced approach combining AI planning with registry fallback.

### Characteristics

- **Default mode**: Used when no explicit mode is chosen
- **Integrated planner**: Registry templates enriched by LLM reasoning
- **Graceful degradation**: AI failure → automatic fallback to registry
- **Moderate autonomy**: AI suggests steps, user can override via permission gate

### Flow

```
Input
  → IntentRouter
  → Context Manager builds context
  → Integrated planner (registry + LLM augmentation)
  → PermissionGate + DLP
  → AgentCore._execute_hybrid():
      - RegistryExecutor for known patterns
      - LLM augmentation for novel situations
      - AutonomousExecutor when appropriate
  → Observe-Reason-Act (limited iterations)
  → Report
```

---

## 4. INTERACTIVE Mode

Every planned step requires explicit user confirmation before execution.

### Characteristics

- **Maximum safety**: User sees each command and must approve
- **Educational**: Best for learning, demonstrations, and CTFs
- **Audit-friendly**: Every step is reviewed and logged
- **Slowest**: Deliberate, step-by-step operation

### Flow

```
Input
  → IntentRouter
  → RegistryPlanner (INTERACTIVE mode)
  → PermissionGate + DLP
  → User approval prompt for each step
  → RegistryExecutor executes approved steps
  → Results shown, user decides next action
```

---

## REPL Architecture

The REPL is a full conversational shell (`siyarix/chat/`):

| Module | Purpose |
|--------|---------|
| `repl.py` | Main REPL entrypoint, event loop, Ctrl+C handling |
| `engine.py` | ReplEngine — message processing, mode routing, agent dispatch |
| `console.py` | Console output formatting, theme application |
| `commands.py` | Built-in commands (help, exit, /mode, /theme, /export, /clear) |
| `handlers.py` | Message handler chain (mode/command/intent/fallback) |
| `event_stream.py` | Real-time event stream for streaming LLM responses |
| `ui.py` | Terminal UI elements (progress bars, spinners, status bars) |
| `prompts.py` | Prompt templates and system prompt management |
| `platform_utils.py` | Cross-platform clipboard, terminal size, OS detection |
| `stubs.py` | Stub agents for demo/testing |
| `openai_compat.py` | OpenAI-compatible streaming adapter |
| `session.py` | ChatSession with branching and export |

### REPL Event Loop

```
┌─────────────────────────────────────────────────────────┐
│                    REPL Event Loop                      │
│                                                         │
│  Wait for user input (prompt_async)                     │
│    ↓                                                    │
│  Check for built-in commands (/, exit)                  │
│    ↓                                                    │
│  Check for mode switch keywords                         │
│    ↓                                                    │
│  Route to agent dispatch                                │
│    ↓                                                    │
│  AgentCore.process_instruction()                        │
│    ↓                                                    │
│  Display streaming response (event_stream.py)           │
│    ↓                                                    │
│  Back to prompt                                         │
└─────────────────────────────────────────────────────────┘
```

### Console Output

```
╭─ Siyarix v2.0.0 ─ AUTONOMOUS ─ 10.0.0.1 ───────────────╮
│                                                           │
│  ℹ [14:32:01] Starting autonomous reconnaissance...      │
│  ℹ [14:32:02] Mode: AUTONOMOUS | Target: 10.0.0.1      │
│                                                           │
│  ╭─ Plan ──────────────────────────────────────────────╮ │
│  │ Step 1: nmap -sV -sC -O 10.0.0.1                    │ │
│  │ Step 2: nikto -h 10.0.0.1                           │ │
│  │ Step 3: enum4linux -a 10.0.0.1                      │ │
│  ╰──────────────────────────────────────────────────────╯ │
│                                                           │
│  ⠋ Step 1: nmap scanning...                              │
│  ✓ Step 1 complete — 6 open ports found                  │
│                                                           │
│  ⠋ Step 2: nikto scanning...                             │
│  ✓ Step 2 complete — 2 findings                          │
│                                                           │
│  ╭─ Findings ──────────────────────────────────────────╮ │
│  │ 10.0.0.1:80 → Apache 2.4.41 (CVE-2024-1234 Medium) │ │
│  │ 10.0.0.1:443 → OpenSSL 1.1.1 (CVE-2024-5678 High)  │ │
│  │ 10.0.0.1:22 → OpenSSH 8.9p1                         │ │
│  ╰──────────────────────────────────────────────────────╯ │
│                                                           │
│  > _                                                      │
╰───────────────────────────────────────────────────────────╯
```

---

## Onboarding Wizard

When Siyarix is first run (no `settings.toml`), it launches the **Onboarding Wizard** (`siyarix/onboarding.py`) — a 11-step interactive setup:

| Step | Description |
|------|-------------|
| 0 | Welcome and introduction |
| 1 | Theme selection (preview each theme) |
| 2 | Default mode selection |
| 3 | Provider configuration (API keys) |
| 4 | Provider testing (test connection) |
| 5 | Security preferences (auto-confirm, DLP sensitivity) |
| 6 | Output preferences (format, verbosity) |
| 7 | Path configuration (workspace, output, offline store) |
| 8 | Learning System (opt-in/out, auto-suggest) |
| 9 | Review preferences summary |
| 10 | Apply configuration and restart |

---

## Batch Mode

Batch mode allows non-interactive execution from stdin or file:

```bash
siyarix --batch commands.txt
```

Each line is processed as a separate instruction. Results are output in the configured format. Best paired with `--output-format json` for programmatic consumption.

---

## REPL Built-in Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `/mode <mode>` | `/m` | Switch agent mode |
| `/theme <theme>` | `/t` | Change theme |
| `/model <model>` | — | Switch AI model |
| `/provider <provider>` | `/p` | Switch provider |
| `/export <format>` | `/e` | Export session |
| `/clear` | `/c` | Clear conversation |
| `/save` | — | Save session |
| `/load <id>` | — | Load saved session |
| `/help` | `/h`, `/?` | Show help |
| `exit` | `quit`, `/q` | Exit REPL |
