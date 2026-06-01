# Persona System

Siyarix uses a persona system to shape the LLM's response style, focus area, and depth of expertise. Personas are dynamic prompt preambles prepended to the unified system prompt before each AI interaction.

## Quick reference

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

## Available personas

| Name | Label | Focus area |
|------|-------|------------|
| `redteam` | Red Team Operator | Offensive security, penetration testing, exploitation |
| `blueteam` | Blue Team Defender | Detection engineering, log analysis, incident response |
| `purpleteam` | Purple Team Engineer | Bridging offensive and defensive security |
| `dfir` | DFIR Specialist | Forensics, timeline reconstruction, artefact analysis |
| `threatintel` | Threat Intelligence Analyst | TTP mapping, IoC analysis, adversary profiling |
| `cloudsec` | Cloud Security Engineer | IAM, container security, serverless, cloud posture |
| `appsec` | Application Security Engineer | SAST, DAST, dependency scanning, secure code review |
| `networksec` | Network Security Engineer | Firewall analysis, network segmentation, protocol analysis |
| `governance` | Governance & Compliance Analyst | Framework assessment, policy review, risk analysis |
| `securityexplorer` | Security Explorer | Learning, experimentation, tool discovery |

### Special modes

| Name | Behavior |
|------|----------|
| `auto` | Analyses the user's request and selects the best-fit persona automatically |
| `universal` | Full-spectrum cybersecurity professional — covers all domains |
| `none` | No persona preamble — uses the neutral system prompt, LLM decides its own voice |

## How it works

### Prompt construction

When the LLM is called, the system prompt is built dynamically:

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

- **`persona = "none"`**: Uses `NEUTRAL_SYSTEM_PROMPT` — a stripped-down prompt with no personality framing.
- **Named persona or `"universal"`**: Prepends the persona's detailed preamble before the full-spectrum `SIYARIX_SYSTEM_PROMPT`.
- **`persona = "auto"`**: The system analyses the request and switches to the best-fit persona automatically before calling the LLM.

### System prompts

Two core prompts exist:

| Constant | Purpose |
|----------|---------|
| `SIYARIX_SYSTEM_PROMPT` | Full-spectrum cybersecurity professional — covers offensive, defensive, investigative, and advisory roles. Used with named personas and universal mode. |
| `NEUTRAL_SYSTEM_PROMPT` | Minimal assistant — no persona framing, no personality. Used when persona is set to `none`. |

## Configuration

Set persona via `/persona` command during a session, or persist it in `settings.toml`:

```toml
persona = "redteam"
```

The setting is read at the start of each LLM interaction, so changes take effect immediately.
