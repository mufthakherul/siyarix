# Persona System

Siyarix uses a persona system to shape the LLM's response style, focus area, and depth of expertise. Personas are dynamic prompt preambles prepended to (or replacing) the system prompt before each AI interaction. The system supports 10 security-domain personas plus special modes for auto-selection, universal coverage, and neutral operation.

---

## Quick Reference

| Command | Effect |
|---------|--------|
| `/persona` | Show current persona |
| `/persona list` | List all available personas |
| `/persona <name>` | Switch to a named persona |
| `/persona auto` | Analyse request and auto-select best-fit persona |
| `/persona universal` | Full-spectrum cybersecurity professional |
| `/persona none` | No persona — neutral assistant |

The current persona is shown in the bottom status line:

```
Time: 12.3s | Mode: integrated | Persona: redteam | LLM: connected
```

---

## Available Personas

| Name | Label | Focus Area | Prompt Theme |
|------|-------|------------|-------------|
| `redteam` | Red Team Operator | Offensive security, penetration testing, exploitation | PTES, OSTMM, TIBER-EU, C2 operations, EDR bypass |
| `blueteam` | Blue Team Defender | Detection engineering, log analysis, incident response | Sigma/YARA/KQL/SPL, PICERL, NIST CSF, threat hunting |
| `purpleteam` | Purple Team Engineer | Bridging offensive and defensive security | Atomic Red Team, Caldera, ATT&CK mapping, detection coverage |
| `dfir` | DFIR Specialist | Forensics, timeline reconstruction, artefact analysis | SAMS forensics, Volatility, Plaso, chain of custody |
| `threatintel` | Threat Intelligence Analyst | TTP mapping, IoC analysis, adversary profiling | Intelligence lifecycle, Diamond Model, STIX, MISP/OpenCTI |
| `cloudsec` | Cloud Security Engineer | IAM, container security, serverless, cloud posture | Prowler, ScoutSuite, kube-bench, zero trust, shared responsibility |
| `appsec` | Application Security Engineer | SAST, DAST, dependency scanning, secure code review | STRIDE/PASTA, OWASP Top 10, Semgrep, CodeQL, SBOM |
| `networksec` | Network Security Engineer | Firewall analysis, network segmentation, protocol analysis | Zeek, Suricata, zero-trust NAC, protocol analysis |
| `governance` | Governance & Compliance Analyst | Framework assessment, policy review, risk analysis | ISO 27001, SOC 2, PCI DSS, NIST CSF 2.0, FAIR |
| `securityexplorer` | Security Explorer | Learning, experimentation, tool discovery | Ghidra/IDA, AFL++, CTFs, CVE research, adversarial ML |

### Special Modes

| Name | Behavior |
|------|----------|
| `auto` | Analyses the user's request and selects the best-fit persona automatically using LLM reasoning |
| `universal` | Full-spectrum cybersecurity professional — covers all domains in a single preamble |
| `none` | No persona preamble — uses `NEUTRAL_SYSTEM_PROMPT`, LLM decides its own voice |

---

## How It Works

### Prompt Construction

When the LLM is called, the system prompt is built dynamically by `_build_system_prompt()`:

```python
def _build_system_prompt(self) -> str:
    persona_name = self._settings.get("persona") or "none"
    if persona_name == "none":
        return NEUTRAL_SYSTEM_PROMPT
    preamble = build_persona_prompt(persona_name)
    if preamble:
        return preamble + "\n\n" + SIYARIX_SYSTEM_PROMPT
    return SIYARIX_SYSTEM_PROMPT
```

**Logic Summary:**

| Persona Setting | System Prompt Used |
|----------------|-------------------|
| `none` | `NEUTRAL_SYSTEM_PROMPT` only |
| Named persona (e.g. `redteam`) | Persona preamble + `SIYARIX_SYSTEM_PROMPT` |
| `universal` | Universal preamble + `SIYARIX_SYSTEM_PROMPT` |
| `auto` | Auto preamble (lists all personas) + `SIYARIX_SYSTEM_PROMPT` |

### Persona Preamble Function

`build_persona_prompt()` in `personas.py` generates the preamble text:

```python
def build_persona_prompt(persona_name: str) -> str:
    p = get_persona(persona_name)
    if not p or persona_name == "none":
        return ""

    if persona_name == "auto":
        lines = ["## Active Persona: Auto (Smart Select)"]
        lines.append("Analyse the user's request and adopt the best-fit persona.")
        for name, pp in PERSONAS.items():
            if name not in ("auto", "none"):
                lines.append(f"  - **{pp['label']}**: {pp['description']}")
        return "\n".join(lines)

    return f"## Active Persona: {p['label']}\n{p['prompt']}"
```

### System Prompts

Two core prompts are defined in `src/siyarix/chat/prompts.py`:

| Constant | Purpose | Size |
|----------|---------|------|
| `SIYARIX_SYSTEM_PROMPT` | Full-spectrum cybersecurity professional — offensive, defensive, forensic, and advisory. Includes platform context, decision logic, output format, quoting rules, and communication standards. | ~100 lines |
| `NEUTRAL_SYSTEM_PROMPT` | Minimal assistant — no persona framing. Includes platform context, output format, and basic communication standards. | ~30 lines |

### Platform Context Injection

Both prompts dynamically inject platform context via `_platform_context()`:

```
## Platform Context
- OS: Windows 10 (AMD64)
- Shell: cmd /c
- WARNING: Windows system detected — commands must use Windows-compatible flags
```

---

## Example Persona: Red Team

```python
"red team": {
    "name": "red team",
    "label": "Red Team / Offensive Security",
    "description": "Adversary emulation, penetration testing, exploitation",
    "prompt": (
        "You are an elite red-team operator who conducts realistic adversary emulation. "
        "You follow established methodologies — PTES, OSTMM, TIBER-EU — and operate "
        "across the full attack lifecycle..."
    ),
}
```

---

## Configuration

Set persona via `/persona` command during a session, or persist it in `settings.toml`:

```toml
persona = "redteam"
```

The setting is read at the start of each LLM interaction, so changes take effect immediately without restart.

---

## Persona Data Model

Personas are defined in `src/siyarix/personas.py` as a dictionary:

```python
PERSONAS: dict[str, dict[str, Any]] = {
    "red team": {
        "name": "red team",
        "label": "Red Team / Offensive Security",
        "description": "Adversary emulation, penetration testing...",
        "prompt": "You are an elite red-team operator...",
    },
    # ... 9 more personas
}
```

### Lookup Functions

```python
get_persona(name: str) -> dict | None    # Case-insensitive lookup
list_personas() -> list[dict]            # All personas (excludes auto, none, universal)
build_persona_prompt(name: str) -> str   # Generate the preamble text
```

---

## Related Modules

| Module | Path | Purpose |
|--------|------|---------|
| `PERSONAS` | `src/siyarix/personas.py` | Persona definitions (10 security personas + 3 special modes) |
| `build_persona_prompt` | `src/siyarix/personas.py:213` | Generates persona preamble text |
| `SIYARIX_SYSTEM_PROMPT` | `src/siyarix/chat/prompts.py:43` | Full-spectrum system prompt |
| `NEUTRAL_SYSTEM_PROMPT` | `src/siyarix/chat/prompts.py:105` | Minimal neutral system prompt |
| `COMPACT_PROMPT` | `src/siyarix/chat/prompts.py:135` | Compact variant for repeated calls |
