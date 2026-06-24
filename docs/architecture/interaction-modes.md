# 🎮 Interaction Modes

Siyarix is designed to adapt to your workflow. We support four distinct interaction modes: **REGISTRY**, **AUTONOMOUS**, **HYBRID**, and **INTERACTIVE**. 

These modes are available across our two primary interfaces: 
- 💻 **CLI**: A powerful command-line interface with intuitive subcommands.
- 💬 **REPL**: An interactive, conversational shell for dynamic engagement.

> [!NOTE]  
> Mode selection typically happens at invocation time, but if you're using the REPL, you can easily switch modes on the fly using natural language commands!

---

## 🎛️ Mode Selection

### 💻 CLI Mode

When invoking Siyarix from your terminal, the mode is seamlessly selected by the `main_callback()` function located in `cli/main.py`.

Here are a few examples of how you can invoke different modes:

```bash
# 🎯 Registry mode (default): Execute a single command from our template registry
siyarix scan 10.0.0.1
siyarix recon example.com

# 🤖 Autonomous mode: Let Siyarix achieve a goal autonomously
siyarix --mode autonomous "Enumerate all services on 10.0.0.0/24"

# 💬 Interactive (REPL) mode: Jump into the conversational shell
siyarix --interactive
# or simply use the shorthand:
siyarix -i

# 📦 Batch mode: Process a list of commands from stdin or a file
siyarix --batch commands.txt

# ℹ️ Other useful commands
siyarix --version  # Check your current version
siyarix --help     # Display help and available options
```

### 💬 REPL Mode Switching

Once inside the REPL, you don't need to memorize complex flags. You can seamlessly switch modes using natural language or simple slash commands:

```
╭─ Siyarix v2.0.0 ─ INTERACTIVE ───────────────────────────╮
│                                                          │
│  ℹ Type 'help' for commands, 'exit' to quit.             │
│  ℹ Use '/mode <mode>' or simply say: 'switch to autonomous'│
│                                                          │
╰──────────────────────────────────────────────────────────╯

> switch to autonomous mode
  ✓ Mode set to AUTONOMOUS — I'll now operate autonomously.

> what mode am i in?
  You're in AUTONOMOUS mode.
```

> [!TIP]  
> Natural language parsing makes mode switching incredibly fast and intuitive. Just talk to Siyarix like a human teammate!

---

## ⚖️ Mode Comparison

Wondering which mode is right for your current task? Here's a quick comparison to help you decide:

| Aspect | 🎯 REGISTRY | 🤖 AUTONOMOUS | 🤝 HYBRID | 💬 INTERACTIVE |
|--------|-------------|---------------|-----------|----------------|
| **AI Required** | No | Yes | Yes | Yes |
| **User Approval** | No | No | No | Yes *(every step)* |
| **Planning** | Heuristic templates | LLM-driven | LLM + Registry | Registry + Approval |
| **Execution** | Deterministic | Full Loop | Auto + Guided | Step-by-step |
| **Best for** | Known operations | Reconnaissance | Complex goals | Teaching & Auditing |
| **Speed** | ⚡ Fastest | 🚀 Fast | 🚶 Moderate | 🐢 Slowest |
| **Risk Profile** | Low | Medium | Medium | Lowest |
| **Autonomy Level** | None | High | Medium | None |

---

## 1️⃣ REGISTRY Mode (Default)

**REGISTRY Mode** executes commands using predefined plan templates directly from our tool registry. It operates completely independently of AI.

### ✨ Characteristics

- **No AI Dependency**: Works perfectly in air-gapped, offline, or degraded network environments.
- **Deterministic**: The same input will *always* produce the same plan. Reliability you can count on.
- **Lightning Fast**: Zero LLM latency ensures instant execution.
- **Maximum Safety**: No AI hallucination and zero unexpected behaviors.

### 🔄 Execution Flow

```text
Input (e.g., scan 10.0.0.1)
  → IntentRouter classifies intent as "scan"
  → RegistryPlanner finds match: "scan" → ["nmap -sV 10.0.0.1", "nmap -sC 10.0.0.1"]
  → PermissionGate validates the action
  → RegistryExecutor safely runs the commands
  → Output is parsed, and findings are stored in the KnowledgeGraph
```

### 🗂️ Tool Hierarchy (RegistryPlanner)

To ensure robustness, templates are carefully organized with primary tools and built-in fallbacks (alternatives):

```yaml
scan:
  primary: nmap
  alternatives: [masscan, rustscan]
  commands:
    - nmap -sV {target} -oX {output}
    - nmap -sC {target} -oX {output}
```

> [!NOTE]  
> If the primary tool isn't installed or fails, Siyarix automatically attempts to use the listed alternatives.

---

## 2️⃣ AUTONOMOUS Mode

**AUTONOMOUS Mode** is our full-autonomy engine. You provide the goal, and the AI handles the planning and execution loop without needing per-step confirmation.

### ✨ Characteristics

- **Goal-Driven**: Give Siyarix an objective, sit back, and let it work.
- **LLM-Driven Planning**: Plans are generated dynamically and adapt to real-time environmental feedback.
- **Observe-Reason-Act (ORA) Loop**: Features a continuous feedback cycle with integrated reflection for smart decision-making.
- **Budget Enforcement**: Strict token and cost limits are applied per session to prevent runaway tasks.
- **Multi-Wave Execution**: The agent progressively refines its understanding across multiple execution waves.

> [!WARNING]  
> Because AUTONOMOUS mode operates independently, it carries a medium risk profile. Always ensure your target scopes and budgets are clearly defined!

### 🔄 Execution Flow

```text
Input ("Enumerate 10.0.0.1")
  → IntentRouter classifies the request
  → Context Manager builds the environmental context
  → AutonomousPlanner drafts the initial ExecutionPlan
  → PermissionGate & DLP (Data Loss Prevention) validate
  → AutonomousExecutor begins the ORA loop
  → Loops until: Objective Met / Max Iterations Hit / Budget Reached / User Interrupts
  → Generates a final summary and comprehensive report
```

### 🔁 The Autonomous Loop in Action

Here is an example of how the AI reasons through a task:

```text
Iteration 1: nmap -sV 10.0.0.1 → finds ports 22, 80, 443 are open
  → Observe: Apache 2.4.41 running on port 80
  → Reason: Apache version is outdated and has known CVEs
  → Act: Execute `nikto -h 10.0.0.1:80`

Iteration 2: nikto discovers /phpmyadmin and /wp-admin
  → Observe: phpMyAdmin detected, WordPress installation found
  → Reason: phpMyAdmin is high-risk; the WordPress version is currently unknown
  → Act: Execute `curl /wp-json` to determine the WordPress version

Iteration 3: WordPress version identified as 5.6.2
  → Observe: Version 5.6.2 confirmed
  → Reason: Version 5.6.2 is vulnerable to known RCE CVEs (e.g., CVE-2021-29447)
  → Act: Verify if the target is in-scope for active exploitation
  → Conclusion: Objective achieved. Target fully enumerated. Report generated!
```

---

## 3️⃣ HYBRID Mode

**HYBRID Mode** is the sweet spot. It offers a balanced approach by combining the dynamic reasoning of AI planning with the rock-solid reliability of registry fallbacks.

### ✨ Characteristics

- **Default AI Mode**: Automatically engaged when no explicit mode is selected but AI capabilities are active.
- **Integrated Planner**: Traditional registry templates are enriched and guided by LLM reasoning.
- **Graceful Degradation**: If the AI fails or loses connection, the system seamlessly falls back to the deterministic registry.
- **Moderate Autonomy**: The AI suggests the best steps, but you can always override them via the Permission Gate.

### 🔄 Execution Flow

```text
Input
  → IntentRouter
  → Context Manager builds context
  → Integrated Planner (Blends Registry + LLM Augmentation)
  → PermissionGate & DLP
  → AgentCore._execute_hybrid():
      - Uses RegistryExecutor for known, predictable patterns
      - Uses LLM augmentation for novel, complex situations
      - Shifts to AutonomousExecutor when appropriate
  → Observe-Reason-Act (capped at limited iterations)
  → Final Report
```

---

## 4️⃣ INTERACTIVE Mode

**INTERACTIVE Mode** puts you entirely in the driver's seat. Every single planned step requires your explicit confirmation before it executes.

### ✨ Characteristics

- **Maximum Safety**: You see and approve every command. Nothing happens without your green light.
- **Educational**: An incredible tool for learning, live demonstrations, and CTF (Capture The Flag) events.
- **Audit-Friendly**: Every step is transparent, reviewed, and logged.
- **Slow & Steady**: Operations are deliberate and step-by-step.

> [!TIP]  
> If you are learning a new tool or auditing a highly sensitive environment, INTERACTIVE mode is your best friend.

### 🔄 Execution Flow

```text
Input
  → IntentRouter
  → RegistryPlanner (Forced into INTERACTIVE mode)
  → PermissionGate & DLP
  → 🛑 User Approval Prompt for EVERY step
  → RegistryExecutor runs the approved steps
  → Results displayed → User decides the next action
```

---

## 🏗️ REPL Architecture

The REPL isn't just a basic prompt; it's a full-featured conversational shell housed in `siyarix/chat/`. Here’s a breakdown of its core components:

| Module | Purpose |
|--------|---------|
| `repl.py` | The main entrypoint, handling the event loop and graceful Ctrl+C exits. |
| `engine.py` | **ReplEngine**: Processes messages, routes modes, and dispatches agents. |
| `console.py` | Manages gorgeous console formatting and theme applications. |
| `commands.py` | Handles built-in commands (e.g., `/help`, `/mode`, `/theme`, `/export`, `/clear`). |
| `handlers.py` | The message handler chain (Mode → Command → Intent → Fallback). |
| `event_stream.py` | Manages real-time event streaming for silky-smooth LLM responses. |
| `ui.py` | Powers terminal UI elements like progress bars, spinners, and status bars. |
| `prompts.py` | Manages prompt templates and core system prompts. |
| `platform_utils.py` | Ensures cross-platform compatibility (clipboard, terminal size, OS detection). |
| `stubs.py` | Stub agents primarily used for quick demos and testing. |
| `openai_compat.py` | A streaming adapter ensuring OpenAI compatibility. |
| `session.py` | **ChatSession**: Handles conversation branching and exporting. |

### 🔄 REPL Event Loop

```text
┌─────────────────────────────────────────────────────────┐
│                    REPL Event Loop                      │
│                                                         │
│  Wait for user input (prompt_async)                     │
│    ↓                                                    │
│  Check for built-in commands (/, exit)                  │
│    ↓                                                    │
│  Check for natural language mode switch keywords        │
│    ↓                                                    │
│  Route to appropriate agent dispatch                    │
│    ↓                                                    │
│  AgentCore.process_instruction()                        │
│    ↓                                                    │
│  Display real-time streaming response                   │
│    ↓                                                    │
│  Return to prompt                                       │
└─────────────────────────────────────────────────────────┘
```

### 🖥️ A Glimpse of the Console

We take pride in our UI. Here is what you can expect to see in the terminal:

```text
╭─ Siyarix v2.0.0 ─ AUTONOMOUS ─ 10.0.0.1 ───────────────╮
│                                                          │
│  ℹ [14:32:01] Starting autonomous reconnaissance...      │
│  ℹ [14:32:02] Mode: AUTONOMOUS | Target: 10.0.0.1        │
│                                                          │
│  ╭─ Plan ──────────────────────────────────────────────╮ │
│  │ Step 1: nmap -sV -sC -O 10.0.0.1                    │ │
│  │ Step 2: nikto -h 10.0.0.1                           │ │
│  │ Step 3: enum4linux -a 10.0.0.1                      │ │
│  ╰─────────────────────────────────────────────────────╯ │
│                                                          │
│  ⠋ Step 1: nmap scanning...                            │
│  ✓ Step 1 complete — 6 open ports found                  │
│                                                          │
│  ⠋ Step 2: nikto scanning...                           │
│  ✓ Step 2 complete — 2 findings                          │
│                                                          │
│  ╭─ Findings ──────────────────────────────────────────╮ │
│  │ 10.0.0.1:80 → Apache 2.4.41 (CVE-2024-1234 Medium)  │ │
│  │ 10.0.0.1:443 → OpenSSL 1.1.1 (CVE-2024-5678 High)   │ │
│  │ 10.0.0.1:22 → OpenSSH 8.9p1                         │ │
│  ╰─────────────────────────────────────────────────────╯ │
│                                                          │
│  > _                                                     │
╰──────────────────────────────────────────────────────────╯
```

---

## 🪄 Onboarding Wizard

First time using Siyarix? If no `settings.toml` is found, Siyarix automatically launches the **Onboarding Wizard** (`siyarix/onboarding.py`). This interactive 11-step process ensures your environment is perfectly tuned:

| Step | Description |
|------|-------------|
| **0** | 👋 Welcome & Introduction |
| **1** | 🎨 Theme Selection (Live previews included!) |
| **2** | ⚙️ Default Mode Selection |
| **3** | 🔑 Provider Configuration (API Keys setup) |
| **4** | 🧪 Provider Testing (Verifies your connections) |
| **5** | 🛡️ Security Preferences (Auto-confirm settings, DLP sensitivity) |
| **6** | 📝 Output Preferences (Format and verbosity levels) |
| **7** | 📂 Path Configuration (Workspace, output dirs, offline store) |
| **8** | 🧠 Learning System (Opt-in/out of auto-suggestions) |
| **9** | 📋 Review Preferences Summary |
| **10**| ✅ Apply Configuration & Restart |

> [!IMPORTANT]  
> The onboarding wizard is critical for securely handling your API keys and setting up your Data Loss Prevention (DLP) baseline. Don't skip the security preferences!

---

## 📦 Batch Mode

Need to run Siyarix as part of a larger pipeline? **Batch mode** allows for robust, non-interactive execution from `stdin` or a provided file.

```bash
siyarix --batch commands.txt
```

Each line in your file is processed as a completely separate instruction. 

> [!TIP]  
> For seamless programmatic consumption in CI/CD or automation scripts, pair batch mode with the JSON output flag: `--output-format json`.

---

## 🛠️ REPL Built-in Commands Reference

Keep this handy! Here are the core built-in slash commands available within the REPL:

| Command | Aliases | Description |
|---------|---------|-------------|
| `/mode <mode>` | `/m` | Switch your current agent mode |
| `/theme <theme>`| `/t` | Change your UI theme on the fly |
| `/model <model>`| — | Switch the active AI model |
| `/provider <provider>`| `/p` | Switch your LLM provider |
| `/export <format>`| `/e` | Export the current session data |
| `/clear` | `/c` | Clear the current conversation history |
| `/save` | — | Save your current session state |
| `/load <id>` | — | Load a previously saved session |
| `/help` | `/h`, `/?` | Display the help menu |
| `exit` | `quit`, `/q` | Gracefully exit the REPL |
