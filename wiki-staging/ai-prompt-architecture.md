# Prompt Architecture

Welcome to the **Prompt Architecture** of Siyarix! This document outlines how Siyarix dynamically constructs the prompts that power its intelligence.

By pulling together system context, your input, session state, persona configurations, rules, and safety constraints, Siyarix builds the perfect prompt for every situation. All prompt templates live in external `.md` files under `src/siyarix/data/prompts/` and are loaded by `data_loader.py` which supports user overrides from `~/.siyarix/data/prompts/`. The final prompt is assembled by `LLMEngineMixin._build_system_prompt()` in `chat/engine.py`.

---

## Prompt Structure

Every request sent to the Large Language Model (LLM) follows a carefully layered structure:

```
[Persona Preamble]         (Optional — loaded from data/personas/ or ~/.siyarix/data/personas/)
[System Prompt]            (Loaded from data/prompts/system.md or system-neutral.md)
[Rules]                    (Loaded from data/rules/RULES.md — all operational rules)
[Platform Context]         (Dynamically generated at runtime by platform_context())
[Custom Instructions]      (Optional — from `additional_system_message` setting)
[Workspace Context]        (Optional — from AGENTS.md or SOUL.md in your workspace)
[Execution Environment]    (Dynamically injected — OS, Shell details)
[Conversation History]     (Chat history, truncated oldest-first)
[User Input]               (What you typed)
```

> This layered approach ensures the LLM has all the context it needs without being overwhelmed by irrelevant details. Platform context and execution environment are generated at runtime so they always reflect the current session.

---

## Data File Layout

All prompt templates, persona definitions, rules, and UI messages are stored as external files:

```
src/siyarix/data/
├── prompts/
│   ├── system.md              # Full system prompt (~65 lines)
│   ├── system-neutral.md      # Neutral system prompt (~30 lines, no persona)
│   ├── compact.md             # Token-saving variant for active personas
│   └── compact-neutral.md     # Token-saving variant for neutral mode
├── personas/
│   ├── index.json             # Persona metadata index (name, label, description, file)
│   ├── red-team.md            # Individual persona prompt files
│   ├── blue-team.md
│   ├── purple-team.md
│   ├── dfir.md
│   ├── threat-intelligence.md
│   ├── cloud-security.md
│   ├── appsec.md
│   ├── network-security.md
│   ├── governance.md
│   ├── security-explorer.md
│   └── universal.md
├── rules/
│   └── RULES.md               # All LLM operational rules in one categorized file
└── messages/
    └── ui.json                 # UI strings: mode hints, mode colors
```

During onboarding, the entire `data/` directory is copied to `~/.siyarix/data/`. At runtime, files are loaded from the user directory first, falling back to the built-in package directory. This lets users customise any prompt, persona, or rule without editing package files (which would be overwritten on upgrade).

---

## Core System Prompts

### `system.md`

This is the full-spectrum system prompt used whenever a specific persona is active, or when running in default universal mode. It covers:

- **Operational Framework**: How to analyse intent, scope, depth, and risk.
- **Decision Logic**: When to use tools (`needs_tools=true`) vs. talk (`needs_tools=false`).
- **Output Format**: Strict JSON response format with field descriptions and examples.
- **Tool Execution**: Reference to the full rules document for construction, safety, and analysis.
- **Communication Standards**: Tone, MITRE ATT&CK references, CVEs, and Markdown formatting.
- **Model Compatibility**: Designed for both safety-aligned and uncensored models.

### `system-neutral.md`

When running without a specific persona (`persona = none`), this minimal prompt is used.

### Compact Variants

To save token usage during long conversations:

| Variant | Purpose |
|---------|---------|
| `compact.md` | Keeps the current persona active, reminding the LLM to follow instructions already received. |
| `compact-neutral.md` | Quick reminder for neutral mode to maintain JSON output format. |

> Compact variants drastically reduce the number of tokens sent in each request, making multi-turn conversations much faster and cheaper!

---

## Rules Document

All operational rules are stored in a single file `data/rules/RULES.md`, categorically organized:

1. **Command Construction Rules** — Shell quoting, platform awareness, tool selection, command safety
2. **Output Analysis Rules** — Finding identification, cross-tool correlation, severity classification, remediation guidance
3. **Communication Rules** — Tone, structured output, references, uncertainty handling
4. **Risk and Safety Rules** — Pre-execution validation, destructive action protocol, rate limiting
5. **Multi-Wave Execution Rules** — Wave strategy, stop conditions, reporting
6. **Model Constraints and Fallbacks** — Censored model handling, provider fallbacks, token management

The rules document is appended to the full system prompt (not to compact prompts) to provide detailed guidance without bloating every request.

---

## Platform Context

Platform context is **dynamically generated at runtime** by `platform_context()` in `chat/prompts.py`, not stored in external files. This is because the OS and shell can change between sessions:

```python
def platform_context() -> str:
    # Detects sys.platform, OS version, shell — generated fresh each call
```

For example, on Windows, Siyarix generates:

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

> This prevents Siyarix from suggesting Linux-only commands when you're running on Windows, reducing errors and frustration.

---

## Persona Preamble

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

Personas are loaded from `data/personas/index.json` (metadata) and individual `.md` files (prompt text). Custom personas can be added to `~/.siyarix/data/personas/custom/` as JSON files. See [Persona System](ai-persona-system.md) for full details.

---

## Custom Instructions & Workspace Context

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

## Message Construction

Before hitting the API, the `build_messages()` function in `openai_compat.py` assembles the final array:

```python
def build_messages(system_prompt, user_prompt, history, *, compat=None):
    messages = []
    if system_prompt:
        role = "developer" if compat and compat.supports_developer_role else "system"
        messages.append({"role": role, "content": system_prompt})
    if history:
        for msg in history:
            if msg.get("role") == "system":
                continue
            messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_prompt})
    return messages
```

---

## System Prompt Refresh

To prevent instruction drift while saving tokens, Siyarix periodically refreshes the system prompt:

```python
def _should_use_compact(self) -> bool:
    return self._llm_calls > 0 and bool(self._llm_calls % self.SYSTEM_REFRESH_INTERVAL)
```

- **First call**: Sends full persona, system prompt, rules, and platform context.
- **Subsequent calls**: Uses compact variants to save tokens.
- **Every N calls**: Re-sends the full prompt to keep the AI sharply focused.

---

## Prompt Bar Rendering

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

## Related Modules

| Module / Function | File Path | Purpose |
|-------------------|-----------|---------|
| `load_system_prompt()` | `src/siyarix/chat/prompts.py` | Loads system.md from data files |
| `load_neutral_prompt()` | `src/siyarix/chat/prompts.py` | Loads system-neutral.md |
| `load_compact_prompt()` | `src/siyarix/chat/prompts.py` | Loads compact.md |
| `load_compact_neutral_prompt()` | `src/siyarix/chat/prompts.py` | Loads compact-neutral.md |
| `load_rules()` | `src/siyarix/chat/prompts.py` | Loads RULES.md |
| `platform_context()` | `src/siyarix/chat/prompts.py` | Generates dynamic platform context |
| `_build_system_prompt()` | `src/siyarix/chat/engine.py` | Master builder — assembles final prompt |
| `build_persona_prompt()` | `src/siyarix/personas.py` | Generates persona preamble from external files |
| `load_text()` / `load_json()` | `src/siyarix/data_loader.py` | Generic data loaders with user-override fallback |
| `build_messages()` | `src/siyarix/chat/openai_compat.py` | Assembles final API message array |
| `make_prompt_bar()` | `src/siyarix/chat/prompts.py` | Draws the terminal UI bar |
| `mode_prompt_hint()` | `src/siyarix/chat/prompts.py` | Generates mode-specific hints |
| `CompactionEngine` | `src/siyarix/compaction.py` | Compresses large conversation histories |
| `BootstrapEngine._copy_builtin_data()` | `src/siyarix/bootstrap.py` | Copies built-in data to ~/.siyarix/ on first run |
