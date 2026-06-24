# 🧠 Prompt Architecture

> [!NOTE]
> 👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Welcome to the **Prompt Architecture** of Siyarix! This document outlines how Siyarix dynamically constructs the prompts that power its intelligence. 

By pulling together system context, your input, session state, persona configurations, and safety constraints, Siyarix builds the perfect prompt for every situation. All prompt definitions live in `src/siyarix/chat/prompts.py` and are pieced together right when they're needed by `LLMEngineMixin._build_system_prompt()` in `chat/engine.py`.

---

## 🏗️ Prompt Structure

Every request sent to the Large Language Model (LLM) follows a carefully layered structure. Think of it as a recipe where each ingredient serves a specific purpose:

```text
[Persona Preamble]        (Optional — Defined by the active persona)
[System Prompt]           (The core instructions: SIYARIX_SYSTEM_PROMPT or NEUTRAL_SYSTEM_PROMPT)
[Custom Instructions]     (Optional — Sourced from your `additional_system_message` settings)
[Workspace Context]       (Optional — Pulled from AGENTS.md or SOUL.md in your workspace)
[Execution Environment]   (Dynamically injected — Details like your OS and Shell)
[Conversation History]    (Your chat history, truncated oldest-first to fit context limits)
[User Input]              (What you actually typed: natural language or a structured command)
```

> [!NOTE]
> This layered approach ensures the LLM has all the context it needs without being overwhelmed by irrelevant details.

---

## ⚙️ Core System Prompts

At the heart of Siyarix are the core system prompts. These set the baseline behavior and rules for the AI.

### 🛡️ `SIYARIX_SYSTEM_PROMPT`

This is the full-spectrum system prompt (~60 lines) used whenever a specific persona is active, or when running in the default universal mode. It covers everything Siyarix needs to know to operate effectively:

- **Platform Context**: Your Operating System, shell environment, and specific warnings (e.g., Windows quirks).
- **Operational Framework**: How to analyze intent, scope, depth, and risk.
- **Decision Logic**: When to use tools (`needs_tools=true`) vs. when to just talk (`needs_tools=false`).
- **Output Format**: Enforcing strict JSON responses.
- **Tool Execution Steps**: How to safely construct shell commands.
- **Shell Quoting Rules**: Best practices for bash compatibility.
- **Available Tool Categories**: Recon, exploitation, web, etc.
- **Output Analysis**: How to synthesize findings post-execution.
- **Communication Standards**: Guidelines on tone, MITRE ATT&CK references, and CVEs.

```python
SIYARIX_SYSTEM_PROMPT = f"""You are Siyarix, an dedicated cybersecurity professional operating in a terminal-driven environment.

{_platform_context()}

## Operational Framework
Analyse every request across four dimensions:
1. **Intent** — Chat/explanation, security operation, or tool analysis?
2. **Scope** — Network, web, cloud, endpoint, identity, mobile, etc.
3. **Depth** — Quick question, multi-step assessment, or deep research?
4. **Risk** — Could any proposed command cause harm?

## Decision Logic
- **needs_tools=true**: Security operation → construct shell commands
- **needs_tools=false**: General chat → respond directly

## Output Format — Always Return Valid JSON
{{ "needs_tools": true/false, "reasoning": "...", "response": "...", "steps": [] }}

## Tool Execution Steps (needs_tools=true)
Each step is a raw shell command. Use the `command` field.

## Shell Quoting Rules
Avoid patterns that break bash quoting. Prefer grep -E over grep -P.

## Output Analysis (post-execution)
Analyse findings like a pentest report. Identify exposures, correlate tools, assign severity.

## Communication Standards
Be technical and precise. Reference CVEs, ATT&CK techniques. Use Markdown."""
```

### ⚖️ `NEUTRAL_SYSTEM_PROMPT`

When Siyarix is running without a specific persona (`persona = none`), it uses this minimal, bare-bones system prompt (~30 lines).

```python
NEUTRAL_SYSTEM_PROMPT = f"""You are Siyarix, a cybersecurity professional in a terminal-driven environment.

{_platform_context()}

## Approach
Analyse every request within cybersecurity. Determine needs_tools vs direct response.

## Output Format — Always Return Valid JSON
{{ "needs_tools": true/false, "reasoning": "...", "response": "...", "steps": [] }}

## Tool Execution Steps (needs_tools=true)
Each step is a raw shell command.

## Communication Standards
Be technical and precise. Explain reasoning. Use Markdown."""
```

### 🗜️ Compact Variants

To save on token usage (and costs!) during a long conversation, Siyarix switches to "compact" prompts for follow-up questions. 

| Variant | Purpose |
|---------|---------|
| `COMPACT_PROMPT` | Keeps the current persona active, reminding the LLM to follow the instructions it already received. |
| `COMPACT_NEUTRAL` | A quick reminder for the neutral Siyarix to maintain its JSON output format. |

> [!TIP]
> Compact variants drastically reduce the number of tokens sent in each request, making multi-turn conversations much faster and cheaper!

---

## 💻 Platform Context

Siyarix is smart enough to adapt to your operating system. The `_platform_context()` function (found in `prompts.py:139`) dynamically injects environmental details right at the top of the system prompt.

For example, on Windows, Siyarix might inject:

```text
## Platform Context
- OS: Windows 10 (AMD64)
- Shell: cmd /c
- WARNING: Windows system detected — commands must use Windows-compatible flags:
  * nmap: use -sT (TCP connect) instead of -sS (SYN scan); omit -O
  * Use forward slashes or escaped backslashes in paths
  * For DNS: use nslookup if dig is unavailable
  * Find binaries with `where` instead of `which`
```

> [!IMPORTANT]
> This prevents Siyarix from suggesting Linux-only commands when you're running on Windows, reducing errors and frustration.

---

## 🎭 Persona Preamble

When you activate a specific persona (like a Red Teamer), Siyarix adds a special preamble to the very beginning of the prompt to set the mood and expertise:

```text
## Active Persona: Red Team / Offensive Security
[Persona-specific expertise paragraph with methodology, tools, and mindset]
```

If you're using `auto` mode, Siyarix gets a list of all available personas and decides for itself which hat to wear based on your request:

```text
## Active Persona: Auto (Smart Select)
Analyse the user's request below and automatically adopt the persona
that best fits the task. Available personas:
  - **Red Team / Offensive Security**: Adversary emulation, penetration testing...
  - **Blue Team / Defensive Security**: Detection engineering, SOC operations...
  ...
```

---

## 🛠️ Custom Instructions & Workspace Context

You can tailor Siyarix to your specific needs! The `_build_system_prompt()` method checks for custom instructions or workspace files and injects them seamlessly.

```python
# 1. Custom instructions from your settings
extra = self._settings.get("additional_system_message", "").strip()
if extra:
    prompt += "\n\n## Custom Instructions\n" + extra

# 2. Workspace context files (like AGENTS.md or SOUL.md)
for filename in ("AGENTS.md", "SOUL.md"):
    ctx_file = Path.cwd() / filename
    if ctx_file.exists():
        content = ctx_file.read_text(encoding="utf-8").strip()
        if content:
            label = filename.replace(".md", "")
            prompt += f"\n\n## {label}\n{content}"

# 3. Finally, add the execution environment
prompt += f"\n\n## Execution Environment\n- OS: {os_name}\n- Shell: {shell}\n- ..."
```

---

## 📜 Conversation History

To hold a cohesive conversation, Siyarix needs to remember what was said. The `ChatSession` handles this, appending recent history to the prompt.

```python
session = ChatSession()
session.add_message("user", "scan 10.0.0.1")
session.add_message("assistant", json_response)
```

### 🗃️ Context Window Management

LLMs have memory limits (the context window). When a conversation gets too long, Siyarix uses several techniques to keep things running smoothly:

1. **Oldest-First Truncation**: Drops the oldest messages when approaching token limits.
2. **Tool Output Summarization**: Condenses verbose tool output (e.g., `nmap output: 5 ports found`).
3. **Knowledge Graph Summarization**: Distills complex data (e.g., `3 hosts, 12 ports, 2 vulns`).
4. **Compaction Engine**: When `CONTEXT_OVERFLOW` hits, the `CompactionEngine` actively uses the LLM to summarize long histories into bite-sized summaries.

> [!WARNING]
> If you notice Siyarix "forgetting" very early details in a large session, it's because the Compaction Engine or truncation has kicked in to keep the context window manageable!

---

## 📤 Output Format

Siyarix is instructed to **always** respond in a strict JSON format. This allows the underlying engine to parse the response and execute tools programmatically.

```json
{
  "needs_tools": true,
  "reasoning": "Step-by-step analysis of the request",
  "response": "Direct answer when needs_tools=false, or analysis post-execution",
  "steps": [
    {
      "tool": "",
      "command": "nmap -sV -p 1-1000 10.0.0.1",
      "description": "Port scan target with service detection"
    }
  ]
}
```

### 📋 Field Reference

| Field | Type | When Present? | Description |
|-------|------|---------------|-------------|
| `needs_tools` | `bool` | Always | Does Siyarix need to run shell commands? |
| `reasoning` | `string` | Always | Siyarix's internal thought process and methodology. |
| `response` | `string` | Always | The final answer, or a summary of what happened after tools ran. |
| `steps` | `array` | `needs_tools=true` | The actual list of commands Siyarix wants to run. |

**Deep dive into `steps`:**

| Sub-field | Type | Description |
|-----------|------|-------------|
| `tool` | `string` | The tool name (can be empty for generic shell commands). |
| `command` | `string` | The exact, raw shell command to execute. |
| `description` | `string` | Why this command is being run and what to look for. |

---

## 🏗️ Message Construction

Before hitting the API, the `build_messages()` function in `openai_compat.py` pieces everything together into the final array format expected by the LLM provider.

```python
def build_messages(system_prompt, user_prompt, history, *, compat=None):
    messages = []
    
    # Add the system prompt (using 'developer' role if supported)
    if system_prompt:
        role = "developer" if compat and compat.supports_developer_role else "system"
        messages.append({"role": role, "content": system_prompt})
        
    # Append conversation history, filtering out old system messages
    if history:
        for msg in history:
            if msg.get("role") == "system":
                continue  
            messages.append({"role": msg["role"], "content": msg["content"]})
            
    # Finally, slap the user's latest input at the very end
    messages.append({"role": "user", "content": user_prompt})
    
    return messages
```

---

## 🔄 System Prompt Refresh

To prevent the LLM from forgetting its core instructions (instruction drift) while still saving tokens with "compact" prompts, Siyarix periodically "refreshes" the system prompt.

```python
def _should_use_compact(self) -> bool:
    return self._llm_calls > 0 and bool(self._llm_calls % self.SYSTEM_REFRESH_INTERVAL)
```

- **First call**: Sends the full persona and system prompt.
- **Subsequent calls**: Uses compact variants to save tokens.
- **Every N calls** (configurable): Blasts the full system prompt again to keep the AI sharply focused.

---

## 🎨 Prompt Bar Rendering

It's not just about what goes *to* the LLM; it's also about what *you* see! `chat/prompts.py` generates the sleek, professional prompt bar in your terminal.

```python
from siyarix.chat.prompts import make_prompt_bar

# Renders something beautiful like this:
# ▌ siyarix  [integrated]  openai  persona:redteam  msgs:42  up:01:23:45  sid:a1b2c3  ▐
# ╰─ ➜ (Tab: autocomplete, ?: help)
```

The prompt bar is packed with info:
- **Mode Indicator**: Color-coded for quick visual cues (cyan for integrated, magenta for autonomous, yellow for offline, red for stealth).
- **Provider Name**: e.g., OpenAI, Anthropic (in blue).
- **Active Persona**: So you never forget who you're talking to (in green).
- **Stats**: Message count and session uptime.
- **Session ID**: A truncated identifier for your current run.
- **Hints**: Context-aware help text tailored to your active mode.

---

## 🗺️ Related Modules

Want to explore the code yourself? Here's your treasure map:

| Module / Function | File Path | Purpose |
|-------------------|-----------|---------|
| `SIYARIX_SYSTEM_PROMPT` | `src/siyarix/chat/prompts.py:171` | The full, heavyweight system prompt. |
| `NEUTRAL_SYSTEM_PROMPT` | `src/siyarix/chat/prompts.py:233` | The minimal, bare-bones prompt. |
| `COMPACT_PROMPT` | `src/siyarix/chat/prompts.py:263` | Token-saving prompt for active personas. |
| `COMPACT_NEUTRAL` | `src/siyarix/chat/prompts.py:268` | Token-saving prompt for neutral mode. |
| `_platform_context()` | `src/siyarix/chat/prompts.py:139` | Injects your OS and shell info. |
| `_build_system_prompt()` | `src/siyarix/chat/engine.py:550` | The master builder! Assembles the final prompt. |
| `build_persona_prompt()` | `src/siyarix/personas.py:218` | Generates the persona expertise preamble. |
| `build_messages()` | `src/siyarix/chat/openai_compat.py` | Assembles the final message array for the API. |
| `make_prompt_bar()` | `src/siyarix/chat/prompts.py:121` | Draws the beautiful terminal UI bar. |
| `mode_prompt_hint()` | `src/siyarix/chat/prompts.py:101` | Generates the helpful hints below the prompt bar. |
| `CompactionEngine` | `src/siyarix/compaction.py` | The hero that compresses huge conversation histories. |
