# 🌊 Multi-Wave Execution & Live Streaming

Siyarix leverages a sophisticated, **multi-wave execution loop** to power its iterative, LLM-driven workflows. Instead of merely firing off a single batch of commands and hoping for the best, Siyarix operates in sequential "waves." 

After each wave, the LLM analyzes the results to intelligently determine the next steps. This progressive approach unlocks truly autonomous, multi-step security operations! Plus, context is seamlessly carried over between waves, empowering the LLM to learn and build upon its previous findings as it works through complex tasks.

> [!NOTE]
> Think of a wave as a single, complete thought process: *Plan ➡️ Execute ➡️ Analyze ➡️ Repeat.*

---

## 🔄 Execution Flow

Here is a simplified look at how the multi-wave loop operates from start to finish:

```text
User Request 
  ↳ LLM Analyzes & Plans 
      ↳ Wave 1 Executes 
          ↳ LLM Analyzes Results 
              ↳ Wave 2 Executes (if needed) 
                  ↳ ... 
                      ↳ Final Response Delivered (capped at a configurable max waves)
```

> [!TIP]
> This continuous feedback loop ensures that every subsequent action is deeply informed by real-time execution results.

---

## 🔁 The Multi-Wave Loop Explained

### 🧠 LLM-Driven Wave Orchestration (Integrated & Autonomous Modes)

At the heart of the system is the `LLMEngineMixin._execute_agent()` method found in `chat/engine.py`. This method acts as the master orchestrator for the multi-wave loop. Here is an inside look at how it works:

```python
max_waves = self._settings.get("max_waves") or 12
plan = llm_plan

for wave in range(max_waves):
    if not plan or not plan.steps:
        break

    # 🚀 Execute via AutonomousExecutor with live display enabled
    plan = await agent.executor_autonomous.execute_plan(plan, live_display=True)

    # 🛑 If cancelled by the user, immediately stop the loop
    if plan.status.name == "CANCELLED":
        break

    # 🗂️ Collect all outputs to build context for the next wave
    for s in plan.steps:
        result = s.result or {}
        output = (result.get("output") or "").strip()
        all_outputs.append(f"• {cmd_label}:\n{output}\n")

    # 🤖 Ask the LLM: Are we done, or is more work needed?
    if llm_connected:
        wave_goal = (
            f"Original request: {instruction}\n\n"
            f"Completed execution wave {wave + 1}. Results so far:\n\n"
            f"{''.join(all_outputs)}\n\n"
            "Analyze these results. Decide: is the original request fully satisfied?\n"
            "- If YES → set needs_tools=false and provide a final response.\n"
            "- If NO and only 1-2 more commands are needed → set needs_tools=true.\n"
            "- Prefer stopping early with a good summary over endless waves."
        )
        plan = await agent.planner_autonomous.plan(
            wave_goal,
            system_prompt=wave_sys_prompt,
            llm_call=llm_call_fn,
            is_first_call=False,
        )
    else:
        plan = None
```

> [!IMPORTANT]
> The orchestrator ensures that Siyarix does not get stuck in an endless loop. It sets a hard limit on waves (`max_waves`, defaulting to 12) and explicitly instructs the LLM to prefer early summarization over unnecessary probing.

### 🧠 Memory & Context Carry-Over

One of the most powerful features of the multi-wave loop is its memory. Each wave's output is collected and injected directly into the LLM's next analysis prompt. 

This rich context package includes:

- **🎯 The Original Request**: The user's initial prompt is preserved across all waves to ensure the system stays focused on the end goal.
- **📈 Historical Outputs**: Accumulated results from *every* executed wave.
- **🛠️ Execution Metadata**: Details like the specific tools used, the exact commands run, and their exit statuses.
- **⏱️ Wave Counter**: Knowing the current wave number helps the LLM gauge its progress and prevent endless loops.

This accumulated context acts as a "short-term memory," allowing the LLM to make highly informed decisions about whether to pivot, drill deeper, or successfully conclude the operation.

### ⚖️ The Wave Decision

At the end of every wave, the LLM takes a step back, reviews the accumulated context, and makes a crucial decision by formulating a new plan:

- **`needs_tools=false`**: The objective is achieved! The LLM will now synthesize the findings and present a polished final response to the user.
- **`needs_tools=true`**: More work is required. The LLM generates a brand-new plan for the next wave (e.g., *Wave 1 found open ports ➡️ Wave 2 will now run vulnerability scans against them*).

---

### ⚙️ AgentCore Multi-Wave (Core Mode)

For programmatic access, `AgentCore.execute_multi_wave()` (located in `core/__init__.py`) provides a structured and deeply integrated multi-wave interface:

```python
async def execute_multi_wave(self, goal: AgentGoal, max_waves: int = 5) -> AgentResult:
    all_findings = []
    plan = None
    for wave in range(max_waves):
        wave_context = {
            "wave": wave,
            "previous_findings": all_findings[-20:],
            "goal": goal.description,
        }
        wave_goal = AgentGoal(
            description=goal.description,
            constraints={**goal.constraints, "context": wave_context},
        )
        wave_result = await self.execute_goal(wave_goal, plan)
        
        all_findings.extend(wave_result.findings)
        
        # Early termination check
        if not wave_result.findings:
            break
            
        # Plan the next wave if supported
        if hasattr(self._planner, "plan_next_wave"):
            plan = self._planner.plan_next_wave(wave_result.findings, goal)
        else:
            plan = None
            
    return AgentResult(goal=goal.description, findings=all_findings, success=True)
```

**Key architectural features:**

- **Context Injection**: The last 20 findings are dynamically injected into each subsequent wave's goal context.
- **Early Termination Mechanism**: If a wave produces zero new findings, the loop smartly breaks to save time and resources.
- **Findings Accumulation**: All discoveries across the waves are automatically merged and deduplicated.

---

## 📺 Live Streaming Display

Watching an LLM run commands blindly can be stressful. To keep users fully informed, Siyarix streams command outputs line-by-line in real-time using the `AutonomousExecutor`!

### 🎨 Display Behaviors

- A clean, focused **Live Panel** displays the output of the currently executing command.
- The UI automatically cycles through commands as they execute and complete.
- **Color-coded borders** provide instant status recognition:
  - 🔵 **Cyan**: Command is actively running.
  - 🟢 **Green**: Command completed successfully (Zero exit code).
  - 🔴 **Red**: Command failed (Non-zero exit code).
- The panel title clearly indicates the exact command running and a brief status summary.

### 📊 Per-Wave Output Summary

Once a wave successfully completes, beautiful summary panels are generated for each executed command:

```text
╭─ ✓ $ nmap -sS -sV -O -Pn example.com ───────────────────╮
│ PORT     STATE  SERVICE    VERSION                       │
│ 22/tcp   open   ssh        OpenSSH 8.9p1                 │
│ 80/tcp   open   http       nginx 1.24.0                  │
│ 443/tcp  open   https      nginx 1.24.0                  │
╰──────────────────────────────────────────────────────────╯
```

---

## 🛡️ Interactive Command Review

Security and control are paramount. Before Siyarix executes *any* shell command, you have the opportunity to interactively review it via the integrated permission gate.

### 🔍 Review Prompt Interface

When command review is active (which is the default setting), Siyarix pauses and presents a clear review panel:

```text
╭──────────────── Command Execution Review ─────────────────╮
│ Tool: raw                                                 │
│ Reason: Raw shell command from LLM plan                   │
│                                                           │
│ nmap -sS -sV -O -Pn example.com                           │
╰───────────────────────────────────────────────────────────╯
Review command [edit/run/step/cancel] (run):
```

Here is how you can interact with the prompt:

| Command | Action |
| :--- | :--- |
| `run` | Execute the command exactly as proposed. |
| `edit` | Drop into an editor to tweak the command before running it. |
| `step` | Execute, but continue to step through commands one by one. |
| `cancel` | Safely abort and skip this specific command. |

### 🎛️ Toggling Review Mode

You can easily manage the review state via built-in slash commands:

```bash
/command on      # Enable review prompt before every command
/command off     # Go full auto: skip reviews and run everything immediately
/command         # Check the current state of the review gate
```

> [!WARNING]
> Using `/command off` gives the LLM full autonomy over shell execution. Ensure you are operating in a safe environment before disabling reviews!

---

## 📈 Wave Summaries & Stats

At the conclusion of each wave, Siyarix prints a clean, unobtrusive stats line at the bottom of the terminal, keeping you updated on the session context:

```text
Time: 12.3s | Mode: integrated | Persona: redteam | LLM: connected
```

---

## 🔒 Comprehensive Safety Integration

Executing AI-generated commands requires a rock-solid safety net. *Every single command*, across *every single wave*, must successfully pass through Siyarix's strict safety pipeline:

1. **🚦 PermissionGate**: A strict two-stage review. It first validates syntax, then performs a danger analysis. It outright blocks critical threats and flags high/medium risks for your explicit review.
2. **🛡️ InputValidator**: Actively scans for and rejects injection patterns (e.g., dangerous shell metacharacters, path traversals, or null bytes).
3. **🔏 DLPEngine**: Automatically scrubs secrets, tokens, and Personally Identifiable Information (PII) from the command outputs before they are processed or displayed.
4. **👀 ShellReview**: The interactive human-in-the-loop prompt (edit/run/step/cancel) detailed above.
5. **🧹 Orphan Process Tracking**: Ensures robust cleanup of hanging processes upon timeouts or user interrupts, preventing resource leaks.

---

## ⚡ CLS Pre-Execution (Integrated Mode)

In Integrated Mode, Siyarix features an intelligent optimization: **Continuous Learning System (CLS) Pre-Execution**. 

Before the LLM even begins its initial planning phase, the CLS may automatically execute cached, high-confidence skills (those with ≥ 80% confidence). By gathering this rich base context *before* Wave 1, Siyarix feeds a much more detailed picture to the LLM's first prompt. 

> [!TIP]
> CLS Pre-Execution dramatically reduces the total number of waves needed to complete a task, significantly speeding up complex operations!

---

## 🕵️‍♂️ Adversarial Review

Before any execution occurs, Siyarix passes the LLM's plan through the `AdversarialTester` (located in `chat/stubs.py`). This component actively hunts for and flags potentially dangerous, destructive, or suspicious command patterns.

```text
┌──────────────────────────────────────────────────────┐
│ 🔍 Adversarial Review (3 findings) — 1 critical      │
│                                                      │
│ 🔴 [CRITICAL] Command uses full disk wipe patterns   │
│    Suggestion: Consider using safe alternatives      │
│ ⚠  [HIGH] Command may expose sensitive data          │
│    Suggestion: Review command parameters             │
└──────────────────────────────────────────────────────┘
```

> [!CAUTION]
> If an adversarial review flags a critical issue, Siyarix will aggressively halt or demand explicit user intervention.

---

## 📚 Related Modules Reference

Looking to dive deeper into the code? Here is a quick map of the modules that power the multi-wave execution loop:

| Module | File Path | Primary Purpose |
| :--- | :--- | :--- |
| **`LLMEngineMixin._execute_agent`** | `src/siyarix/chat/engine.py:619` | The core multi-wave execution orchestrator, handling context carry-over. |
| **`AgentCore.execute_multi_wave`** | `src/siyarix/core/__init__.py:286` | Structured multi-wave execution interface designed for programmatic use. |
| **`AutonomousExecutor.execute_plan`** | `src/siyarix/executor_autonomous.py` | The execution engine responsible for the live terminal display. |
| **`AutonomousPlanner.plan`** | `src/siyarix/planner_autonomous.py` | The LLM-driven planner that analyzes wave results and generates the next steps. |
| **`safe_run_async_stream`** | `src/siyarix/subprocess_utils.py` | Async subprocess handler providing line-by-line streaming output. |
| **`ShellReview`** | `src/siyarix/shell_review.py` | Handles the interactive command review prompt (edit/run/step/cancel). |
| **`PermissionGate`** | `src/siyarix/permission_gate.py` | Executes the two-stage syntax and danger validation checks. |
