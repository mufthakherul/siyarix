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

---

## Available Personas

### Named Personas

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

Personas are defined across two file types:

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

The `build_persona_prompt()` function in `personas.py` loads persona data from external files and generates the preamble:

```python
def build_persona_prompt(persona_name: str) -> str:
    p = get_persona(persona_name)
    if not p or persona_name == "none":
        return ""

    if persona_name == "auto":
        lines = ["## Active Persona: Auto (Smart Select)"]
        lines.append("Analyse the user's request below and automatically adopt...")
        for name, pp in _get_personas().items():
            if name not in ("auto", "none"):
                lines.append(f"  - **{pp['label']}**: {pp['description']}")
        return "\n".join(lines)

    return f"## Active Persona: {p['label']}\n{p['prompt']}"
```

### Logic Summary

| Active Setting | Initial Request | Follow-up (Compact) |
|----------------|-----------------|---------------------|
| `none` | `system-neutral.md` only | `compact-neutral.md` |
| Named (e.g., `redteam`) | Persona preamble + `system.md` + `RULES.md` | Persona label + `compact.md` |
| `universal` | Universal preamble + `system.md` + `RULES.md` | Persona label + `compact.md` |
| `auto` | Auto preamble (lists options) + `system.md` + `RULES.md` | Persona label + `compact.md` |

### Data Loading

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

## Configuration

Set a persistent default in `settings.toml`:

```toml
persona = "redteam"
additional_system_message = "Always output findings as a Markdown table"
```

Custom instructions are appended after the system prompt and rules document.

---

## Integration with Interaction Modes

Personas apply to all LLM-dependent modes (`integrated`, `autonomous`, `hybrid`). In `registry` or `offline` modes, the persona system is bypassed entirely (no LLM calls).

---

## Related Modules

| Module / Function | Path | Purpose |
|--------|--------|---------|
| `_load_personas()` | `src/siyarix/personas.py` | Loads all personas from external files + custom dir |
| `build_persona_prompt()` | `src/siyarix/personas.py` | Assembles the persona preamble text |
| `list_custom_personas()` | `src/siyarix/data_loader.py` | Lists custom personas from user directory |
| `load_text()` / `load_json()` | `src/siyarix/data_loader.py` | Generic data loaders with fallback |
| `system.md` | `src/siyarix/data/prompts/system.md` | Full system prompt template |
| `RULES.md` | `src/siyarix/data/rules/RULES.md` | All operational rules |
