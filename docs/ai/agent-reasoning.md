# 🧠 Agent Reasoning Pipeline

!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Welcome to the **Agent Reasoning Pipeline**! This is the "brain" of Siyarix, responsible for taking a user's objective and turning it into real, executed actions.

Think of it as a smart traffic cop: the **Planner Router** directs requests to either an AI-driven planner (using a Large Language Model or LLM) or a rule-based heuristic planner. This depends on the mode you are running. In autonomous mode, the system follows a dynamic **Observe–Reason–Act–Reflect** loop. In registry or offline mode, it relies on reliable, deterministic templates.

!!! note
    The dual-planner architecture ensures that Siyarix remains fully functional whether you have an active LLM connection or are operating completely offline.

---

## 🏛️ Planner Architecture

Siyarix utilizes a two-planner system, all smoothly coordinated by a unified `Planner` router:

```text
User Request
    │
    ▼
┌─────────────────────────────────────────┐
│            Planner Router               │
│  (src/siyarix/planner.py)              │
│                                         │
│  mode == "autonomous" ──► AutonomousPlanner │
│  mode == "registry"   ──► RegistryPlanner   │
│  mode == "offline"    ──► RegistryPlanner   │
│  mode == "integrated" ──► try Autonomous →   │
│                            fallback Registry  │
└─────────────────────────────────────────┘
```

### 🤖 AutonomousPlanner
*(Found in `src/siyarix/planner_autonomous.py`)*

This is our pure, AI-driven planner. It relies entirely on the LLM to figure things out—from verifying if tools are available to installing missing ones and writing the exact shell commands needed.

**Key Features:**
- **🧠 Session-aware Token Optimization**: We save on processing costs by sending full tool details only on the first call. Later calls use a much shorter, compact prompt.
- **🗣️ Multi-format Response Parsing**: Whether the LLM replies in JSON, YAML, Markdown, XML, or just plain text, our system can understand and extract the commands.
- **🛠️ Native Tool Calling**: When available, we prefer structured tool calls directly from the LLM for better accuracy.
- **🛡️ Structured Execution (`execute_plan`)**: We provide the LLM with a strict function definition to ensure the plan it generates is properly formatted and safe.

!!! tip
    The `AutonomousPlanner` works best when the LLM provider supports native structured tool calling (like OpenAI's `tool_calls`).

### ⚙️ RegistryPlanner
*(Found in `src/siyarix/planner_registry.py`)*

This is our reliable, deterministic planner. It operates entirely without an LLM!

**Key Features:**
- **🔍 Keyword Matching**: It uses an inverted keyword index to map plain English words to specific security tools.
- **📋 Pre-built Templates**: It features over 25 predefined templates (like `recon_full`, `network_scan`, `linux_privesc`) to handle common workflows out of the box.
- **🎯 Intent Extraction**: A Natural Language Parser picks up on what you want to do (intent) and what you want to target.
- **🔄 Smart Fallbacks**: If your first-choice tool isn't installed, it automatically rolls over to the next best thing (e.g., swapping `nmap` for `masscan`).

---

## 🚀 Execution Modes

The `AgentCore` module (`src/siyarix/core/__init__.py`) is the main engine, and it supports four different ways of running:

| Mode | Planner Used | Executor Used | Needs an LLM? |
|------|--------------|---------------|---------------|
| **`REGISTRY`** | RegistryPlanner | RegistryExecutor | No ❌ |
| **`AUTONOMOUS`** | AutonomousPlanner | AutonomousExecutor | Yes ✅ |
| **`HYBRID`** | AutonomousPlanner → RegistryPlanner | Both | Optional ⚠️ |
| **`INTERACTIVE`** | RegistryPlanner | RegistryExecutor (needs your OK) | No ❌ |

---

## 🔄 The Observe–Reason–Act–Reflect Loop

When running in **Autonomous Mode**, Siyarix works in a continuous, multi-turn loop—just like a human expert would! Here is how the `LLMEngineMixin._execute_agent()` method handles it:

### 1️⃣ Observe
First, the agent looks around to understand its environment. It collects:
- **Environment State**: Operating system, available tools, current directory.
- **Session State**: What have we talked about so far? What were the results of the last commands?
- **Target Context**: IPs, domains, or URLs you specified.
- **Tool Availability**: A quick check of the `ToolRegistry` to see what is installed.

### 2️⃣ Reason
Next, the LLM puts on its thinking cap. We send it a structured prompt containing the system instructions, conversation history, tool schemas, and your goal.

It then returns a structured plan, looking something like this:

```json
{
    "needs_tools": true,
    "reasoning": "I need to check for open ports to identify running services.",
    "steps": [
        {
            "command": "nmap -sV -p 1-1000 10.0.0.1",
            "description": "Port scan target with service detection"
        }
    ]
}
```

### 3️⃣ Act
Now it's time to execute the plan! The commands are run in "waves." Before anything actually runs, it goes through a rigorous safety check:
1. **PermissionGate**: Checks for syntax errors and dangerous commands.
2. **Input Validation**: Prevents sneaky stuff like shell injection or path traversal.
3. **Shell Review**: (Optional) Prompts you to approve, edit, or cancel the command.
4. **Execution**: Runs the command safely with a timeout and tracks any stray processes.
5. **DLP & Secret Redaction**: Automatically scrubs API keys, passwords, and sensitive tokens from the output before the LLM sees it.

!!! warning
    Security is our top priority. The agent will never run highly destructive commands without explicit review, and sensitive data is aggressively redacted!

### 4️⃣ Reflect
Finally, the LLM reviews the output of the commands. Did we get what we needed?
- If yes, it sets `needs_tools=false` and provides a final answer.
- If no, it sets `needs_tools=true` and creates a new plan for the next wave.

!!! info
    The agent can loop up to **12 waves** per instruction by default. If it hits that limit, it will stop and ask you for further guidance.

---

## 🔧 Tool Call Repair

Sometimes, LLMs get confused and spit out tool calls as plain text instead of structured JSON. No problem! The `ToolCallRepair` module acts as a safety net to parse and fix these mistakes automatically.

### Supported Formats

| Syntax | Example |
|--------|---------|
| **Bracket** | `[nmap]{"target": "10.0.0.1", "flags": "-sV"}` |
| **XML** | `<function=nmap><parameter=target>10.0.0.1</parameter></function>` |
| **Function Call** | `function_call: {"name": "nmap", "args": {...}}` |

### 🎯 Fuzzy Name Matching
If the LLM makes a typo (like calling `nmaps` instead of `nmap`), our fuzzy matching kicks in. It can tolerate minor spelling mistakes, case differences, and substrings to keep the pipeline moving smoothly.

---

## 🛡️ Shell Review

Want to keep a close eye on what the agent is doing? `shell_review.py` provides an interactive prompt for you to review commands before they run.

```text
╭──────────────── Command Execution Review ─────────────────╮
│ Tool: raw                                                 │
│ Reason: Raw shell command from LLM plan                   │
│                                                           │
│ nmap -sS -sV -O -Pn example.com                           │
╰───────────────────────────────────────────────────────────╯
Review command [edit/run/step/cancel] (run):
```

- **`run`**: Execute as-is.
- **`edit`**: Tweak the command first.
- **`step`**: Run commands one by one.
- **`cancel`**: Skip it entirely.

!!! note
    In automated environments (like CI/CD pipelines), Shell Review automatically approves commands so it doesn't get stuck waiting for human input.

---

## 🛟 Heuristic Fallback (Registry Mode)

When your LLM is down, offline, or just unreachable, the `RegistryPlanner` steps in to save the day using deterministic logic.

Here is how it thinks:
1. You say: *"scan 10.0.0.1"*
2. It extracts intent: **"scan"**
3. It extracts target: **"10.0.0.1"**
4. It matches a template: **`network_scan`**
5. It builds a multi-step plan using tools like `nmap`, `whatweb`, and `nuclei`.

### 📑 Popular Templates
| Template Name | What it Runs |
|---------------|--------------|
| `recon_full` | nmap → whatweb → gobuster → subfinder → amass → nuclei |
| `web_audit` | curl → whatweb → nuclei → ffuf → wpscan → nikto |
| `linux_privesc`| uname → find SUID → find writable → cat cron |

---

## ⚡ Dependency Resolution & Parallel Execution

Siyarix is smart about how it runs tasks. It organizes steps into **Layers**.

```text
Layer 1: Recon (Runs immediately)
Layer 2: Scan (Waits for Recon to finish)
Layer 3: Enumerate (Waits for Scan to finish)
```

Tasks within the same layer (like scanning 5 different ports) run **concurrently** to save time, making your scans lightning fast! ⚡

---

## 📊 Result Synthesis

Once the agent has finished all its waves, it doesn't just dump raw text on you. It synthesizes the data:
1. **Deduplicates**: Removes repeated findings (based on target, port, and vulnerability).
2. **Correlates**: Connects the dots between different tools.
3. **Scores Severity**: Tags issues as Critical, High, Medium, Low, or Info.
4. **Summarizes**: Gives you a clean, easy-to-read report.
5. **Logs to Graph**: Saves the findings into a knowledge graph so it remembers them for next time.

---

## 🩺 Validation & Recovery

Things fail. Ports are closed, tools crash. The `Validator` class (`src/siyarix/validators.py`) is our safety net, offering step-level validation and smart recovery.

If a step fails, the agent can:
- **`RETRY`**: Try again with a slight change (e.g., adding `-Pn` to an nmap scan).
- **`RETRY_ALTERNATIVE`**: Switch tools completely (e.g., if `nuclei` fails, try `nikto`).
- **`SKIP`**: Just move on to the next step.
- **`DEGRADE`**: Fall back to a simpler execution mode.

---

## 🗂️ Related Modules Reference

Curious about the code? Here is where everything lives:

| Module | Location | What it Does |
|--------|----------|--------------|
| **Planner Router** | `src/siyarix/planner.py` | The main traffic cop |
| **AutonomousPlanner**| `src/siyarix/planner_autonomous.py` | The LLM-driven AI planner |
| **RegistryPlanner** | `src/siyarix/planner_registry.py` | The offline, rule-based planner |
| **AgentCore** | `src/siyarix/core/__init__.py` | Central orchestrator |
| **LLMEngineMixin** | `src/siyarix/chat/engine.py` | Agent loop with multi-wave planning |
| **ToolCallRepair** | `src/siyarix/tool_call_repair.py` | Fixes broken LLM tool calls |
| **ShellReview** | `src/siyarix/shell_review.py` | Interactive command approval |
| **Validator** | `src/siyarix/validators.py` | Error handling and recovery |
| **ToolRegistry** | `src/siyarix/registry.py` | Tool discovery and capability indexing |
| **ToolCapabilityGraph** | `src/siyarix/tool_graph.py` | Tool chaining and similarity graph |
| **ToolAvailability** | `src/siyarix/tool_availability.py` | Pre-execution availability evaluation |
| **DangerAnalyzer** | `src/siyarix/security_hardening.py` | Keeps dangerous commands in check |
| **CompactionEngine** | `src/siyarix/compaction.py` | Context window compaction for long histories |
