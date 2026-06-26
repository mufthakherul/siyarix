# Persona System

Siyarix leverages a **Persona System** to dynamically adapt the LLM's response style, focus areas, and depth of expertise. Personas act as dynamic prompt preambles injected into the system prompt before each AI interaction.

Personas are defined in external files:
- **Built-in personas**: `src/siyarix/data/personas/` (shipped with package, read-only)
- **Custom personas**: `~/.siyarix/data/personas/custom/` (user-created, writable)
- **Load order**: User directory checked first, falls back to built-in

The system supports **10 specialised security-domain personas** plus **3 special modes**.

---

## Quick Reference

| Command | Effect |
|---------|--------|
| `/persona` | View currently active persona |
| `/persona list` | List all available personas |
| `/persona <name>` | Switch to a named persona |
| `/persona auto` | Smart auto-selection based on request |
| `/persona universal` | Full-spectrum cybersecurity professional |
| `/persona none` | Neutral mode (no persona framing) |

> You can always check which persona is currently active in the status line:
> ```text
> Time: 12.3s | Mode: integrated | Persona: redteam | LLM: connected
> ```

---

## Available Personas

### Named Personas

Each named persona specializes in a specific domain of cybersecurity, equipped with relevant knowledge and frameworks.

| Name | Label | Focus Area | Key Tooling & Frameworks |
|------|-------|------------|--------------------------|
| `redteam` | Red Team / Offensive Security | Adversary emulation, exploitation, evasion | PTES, Cobalt Strike, BloodHound, Chisel |
| `blueteam` | Blue Team / Defensive Security | Detection engineering, threat hunting, IR | Sigma, YARA, Velociraptor, osquery, Zeek |
| `purpleteam` | Purple Team / Collaborative Security | Attack validation, detection coverage | Atomic Red Team, Caldera, ATT&CK |
| `dfir` | DFIR / Digital Forensics | Forensic analysis, malware triage | Volatility, Plaso, Autopsy |
| `threatintel` | Threat Intelligence (CTI) | Threat research, IoC extraction | Diamond Model, STIX, MISP, OpenCTI |
| `cloudsec` | Cloud Security (CloudSec) | AWS/Azure/GCP hardening, containers | Prowler, ScoutSuite, trivy |
| `appsec` | Application Security (AppSec) | Secure code review, SAST/DAST | OWASP Top 10, Semgrep, CodeQL |
| `networksec` | Network Security (NetSec) | Network architecture, firewalls | Zeek, Suricata, Wireshark |
| `governance` | Governance / GRC | Compliance, risk management, audits | ISO 27001, SOC 2, NIST CSF |
| `securityexplorer` | Security Explorer / Research | Vuln research, reverse engineering, CTFs | Ghidra, AFL++, CVE research |

### Special Modes

| Name | Behaviour |
|------|-----------|
| `auto` | **Smart Select**: Analyses your prompt and uses LLM reasoning to pick the best-fit persona |
| `universal` | **The Swiss Army Knife**: Combines all domain expertise into one balanced professional |
| `none` | **Neutral Mode**: Strips all persona framing, uses bare system prompt |

---

## Data File Layout

Personas are defined across two file types stored under `data/personas/`:

### Persona Index (`index.json`)

```json
{
  "red team": {
    "name": "red team",
    "label": "Red Team / Offensive Security",
    "description": "Adversary emulation, penetration testing, exploitation, C2 operations, evasion",
    "file": "red-team.md"
  }
}
```

### Persona Prompt Files (`red-team.md`, `blue-team.md`, etc.)

Each file contains the persona's expertise paragraph, loaded at runtime:

```markdown
You are an elite red-team operator who conducts realistic adversary emulation...
```

### Custom Personas (`~/.siyarix/data/personas/custom/*.json`)

Users can add custom personas as JSON files with `name`, `label`, `description`, and `prompt` fields:

```json
{
  "name": "my-specialist",
  "label": "My Specialist Persona",
  "description": "Custom persona for specialised tasks",
  "prompt": "You are a specialist in..."
}
```

---

## How It Works Under the Hood

### Prompt Construction

When the AI is invoked, the system dynamically builds its prompt using the `_build_system_prompt()` method inside `chat/engine.py`. Prompt templates are loaded from external data files rather than being hardcoded in Python:

```python
def _build_system_prompt(self, compact: bool = False) -> str:
    from ..personas import build_persona_prompt, get_persona
    from .prompts import (
        load_compact_neutral_prompt,
        load_compact_prompt,
        load_neutral_prompt,
        load_system_prompt,
        load_rules,
        platform_context,
    )

    persona_name = self._settings.get("persona") or "auto"

    if compact:
        if persona_name == "none":
            prompt = load_compact_neutral_prompt()
        else:
            p = get_persona(persona_name)
            label = p["label"] if p else "default"
            prompt = f"## Active Persona: {label}\n{load_compact_prompt()}"
    elif persona_name == "none":
        prompt = load_neutral_prompt()
    else:
        preamble = build_persona_prompt(persona_name)
        system_prompt = load_system_prompt()
        if preamble:
            prompt = preamble + "\n\n" + system_prompt
        else:
            prompt = system_prompt

    # Rules and platform context appended for full prompts
    if not compact:
        prompt += "\n\n" + load_rules()
        prompt += "\n\n" + platform_context()
    return prompt
```

### Logic Summary

| Active Setting | Initial Request | Follow-up (Compact) |
|----------------|-----------------|---------------------|
| `none` | `system-neutral.md` only | `compact-neutral.md` |
| Named (e.g., `redteam`) | Persona preamble + `system.md` + `RULES.md` | Persona label + `compact.md` |
| `universal` | Universal preamble + `system.md` + `RULES.md` | Persona label + `compact.md` |
| `auto` | Auto preamble (lists options) + `system.md` + `RULES.md` | Persona label + `compact.md` |

### Persona Preamble Generation

The `build_persona_prompt()` function in `personas.py` loads persona data from external files and generates the preamble:

```python
def build_persona_prompt(persona_name: str) -> str:
    p = get_persona(persona_name)
    if not p or persona_name == "none":
        return ""

    if persona_name == "auto":
        lines = ["## Active Persona: Auto (Smart Select)"]
        lines.append(
            "Analyse the user's request below and automatically adopt the persona "
            "that best fits the task. Available personas:"
        )
        for name, pp in _get_personas().items():
            if name not in ("auto", "none"):
                lines.append(f"  - **{pp['label']}**: {pp['description']}")
        return "\n".join(lines)

    return f"## Active Persona: {p['label']}\n{p['prompt']}"
```

### Data Loading Flow

Personas are loaded by `personas.py` through `data_loader.py`:

1. Load `index.json` from `data/personas/` (user dir first, built-in fallback)
2. Load each `.md` prompt file referenced in the index
3. Load custom personas from `~/.siyarix/data/personas/custom/*.json`
4. Merge all into a single cache

The `auto` and `none` special modes are always defined in code (not external files) since they have special logic.

---

## Persona Data Model

```python
PERSONAS = {
    "red team": {
        "name": "red team",
        "label": "Red Team / Offensive Security",
        "description": "Adversary emulation...",
        "prompt": "You are an elite red-team operator...",
    },
    # ... built-in personas loaded from data files
    "my-custom": {
        "name": "my-custom",
        "label": "My Custom Persona",
        "description": "...",
        "prompt": "...",
    },  # Loaded from ~/.siyarix/data/personas/custom/
    "auto": { ... },    # Special mode (always in code)
    "none": { ... },    # Special mode (always in code)
}
```

### Key Functions

```python
get_persona(name: str) -> dict | None             # Case-insensitive lookup
get_all_personas() -> dict                        # Full dict (including special modes)
list_personas() -> list[dict]                     # Standard named personas only
list_all_personas() -> list[dict]                 # All personas (including special + custom)
build_persona_prompt(name: str) -> str            # Generate the prompt preamble text
reload_personas() -> None                         # Force reload from external files
```

> Persona lookups are fuzzy! `_normalize_persona_key()` strips spaces, hyphens, and underscores. `/persona red-team` works the same as `/persona redteam`.

---

## Example Persona: Red Team

Curious how a persona actually looks? The red team persona is defined across two files:

### `index.json` entry:

```json
"red team": {
    "name": "red team",
    "label": "Red Team / Offensive Security",
    "description": "Adversary emulation, penetration testing, exploitation, C2 operations, evasion",
    "file": "red-team.md"
}
```

### `red-team.md` prompt content:

```markdown
You are an elite red-team operator who conducts realistic adversary emulation. You follow
established methodologies — PTES, OSTMM, TIBER-EU — and operate across the full attack
lifecycle: reconnaissance, weaponisation, delivery, exploitation, installation, C2, and
exfiltration. You chain low-severity weaknesses into high-impact compromise paths,
bypass modern defences (EDR, ASLR, CFG, AMSI), and maintain covert C2 with operational
security. Your toolkit includes Cobalt Strike, Mythic, Sliver, BloodHound, Mimikatz,
Rubeus, Certipy, Impacket, Chisel, and custom tooling. You think in assumptions of
breach and test every control as if a nation-state adversary is the benchmark.
```

---

## Configuration

You don't need to restart Siyarix to change your persona. You can switch dynamically using the `/persona` command, or set a persistent default in your `settings.toml` file:

```toml
persona = "redteam"
additional_system_message = "Always output findings as a Markdown table"
```

Custom instructions are appended after the system prompt and rules document.

> The configuration is evaluated at the start of every LLM interaction, meaning any changes you make will take effect immediately.

---

## Integration with Interaction Modes

Personas apply to all LLM-dependent modes (`integrated`, `autonomous`, `hybrid`). In `registry` or `offline` modes, the persona system is bypassed entirely (no LLM calls).

---

## Related Modules

| Module / Function | Path | Purpose |
|--------|--------|---------|
| Persona data files | `src/siyarix/data/personas/index.json` + `.md` files | Persona definitions (index + prompt text) |
| `_load_personas()` | `src/siyarix/personas.py` | Loads all personas from external files + custom dir |
| `build_persona_prompt()` | `src/siyarix/personas.py` | Assembles the persona preamble text |
| `list_custom_personas()` | `src/siyarix/data_loader.py` | Lists custom personas from user directory |
| `load_text()` / `load_json()` | `src/siyarix/data_loader.py` | Generic data loaders with built-in/user fallback |
| `system.md` | `src/siyarix/data/prompts/system.md` | Full system prompt template |
| `system-neutral.md` | `src/siyarix/data/prompts/system-neutral.md` | Neutral system prompt template |
| `compact.md` | `src/siyarix/data/prompts/compact.md` | Token-saving prompt variant |
| `compact-neutral.md` | `src/siyarix/data/prompts/compact-neutral.md` | Token-saving neutral variant |
| `RULES.md` | `src/siyarix/data/rules/RULES.md` | All operational rules |
| `_build_system_prompt` | `src/siyarix/chat/engine.py` | The core function that stitches everything together |
