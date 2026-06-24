# 🎭 Persona System

> [!NOTE]
> 👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Siyarix leverages a **Persona System** to dynamically adapt the LLM's response style, focus areas, and depth of expertise. Think of personas as specialized hats that the AI wears to better suit your specific security needs. These personas act as dynamic prompt preambles that are injected into the system prompt right before each AI interaction. 

Currently, the system supports **10 specialized security-domain personas** along with **3 special modes** designed for auto-selection, comprehensive coverage, and neutral operations.

---

## 🚀 Quick Reference

Want to switch things up quickly? Here are the slash commands to control your active persona:

| Command | Effect |
|---------|--------|
| `/persona` | 🔍 View your currently active persona. |
| `/persona list` | 📋 List all available personas you can choose from. |
| `/persona <name>` | 🎭 Switch to a specific named persona. |
| `/persona auto` | 🤖 Let Siyarix analyze your request and automatically select the best-fit persona. |
| `/persona universal` | 🌐 Activate the full-spectrum cybersecurity professional (covers all domains). |
| `/persona none` | ⚪ Use no specific persona, making the assistant act completely neutral. |

> [!TIP]
> You can always check which persona is currently active by glancing at the bottom status line in your terminal:
> ```text
> Time: 12.3s | Mode: integrated | Persona: redteam | LLM: connected
> ```

---

## 🛡️ Available Personas

### 🏷️ Named Personas

Each named persona specializes in a specific domain of cybersecurity, equipped with relevant knowledge and frameworks.

| Name | Label | Focus Area | Key Tooling & Frameworks |
|------|-------|------------|-------------|
| `redteam` | 🔴 Red Team / Offensive Security | Adversary emulation, penetration testing, exploitation, evasion | PTES, Cobalt Strike, BloodHound, Chisel |
| `blueteam` | 🔵 Blue Team / Defensive Security | Detection engineering, threat hunting, incident response, SOC ops | Sigma, YARA, Velociraptor, osquery, Zeek |
| `purpleteam` | 🟣 Purple Team / Collaborative Security | Attack validation, detection coverage, adversary emulation | Atomic Red Team, Caldera, ATT&CK mapping |
| `dfir` | 🔎 DFIR / Digital Forensics | Forensic analysis, malware triage, timeline reconstruction | Volatility, Plaso, Autopsy, chain of custody |
| `threatintel` | 🧠 Threat Intelligence (CTI) | Threat research, IoC extraction, threat actor profiling | Diamond Model, STIX, MISP, OpenCTI |
| `cloudsec` | ☁️ Cloud Security (CloudSec) | AWS/Azure/GCP hardening, container security, Kubernetes | Prowler, ScoutSuite, trivy, zero trust |
| `appsec` | 💻 Application Security (AppSec) | Secure code review, SAST/DAST, threat modeling, supply chain | OWASP Top 10, Semgrep, CodeQL, SBOM |
| `networksec` | 🌐 Network Security (NetSec) | Network architecture, firewalls, protocol analysis, segmentation | Zeek, Suricata, Wireshark, microsegmentation |
| `governance` | 🏛️ Governance / GRC | Compliance, risk management, policy frameworks, audits | ISO 27001, SOC 2, NIST CSF 2.0, FedRAMP |
| `securityexplorer`| 🔬 Security Explorer / Research | Vulnerability research, reverse engineering, CTFs, fuzzing | Ghidra, AFL++, CVE research, adversarial ML |

### ✨ Special Modes

Sometimes you need flexibility over specialization. These special modes adjust how the persona system operates on a broader scale:

| Name | Behavior |
|------|----------|
| `auto` | **Smart Select:** Analyzes your prompt and uses LLM reasoning to automatically pick the best-fit persona. It feeds all available persona descriptions to the AI so it can make an informed choice! |
| `universal` | **The Swiss Army Knife:** Combines all domain expertise into a single, balanced cybersecurity professional. Covers Red, Blue, Purple, Cloud, AppSec, and more in one prompt. |
| `none` | **Neutral Mode:** Strips away all persona framing. The LLM decides its own voice based purely on the `NEUTRAL_SYSTEM_PROMPT` and basic platform context. |

---

## ⚙️ How It Works Under the Hood

### 🛠️ Prompt Construction

When the AI is invoked, the system dynamically builds its prompt using the `_build_system_prompt()` method inside `chat/engine.py`.

```python
def _build_system_prompt(self, compact: bool = False) -> str:
    persona_name = self._settings.get("persona") or "auto"

    if compact:
        if persona_name == "none":
            prompt = COMPACT_NEUTRAL
        else:
            p = get_persona(persona_name)
            label = p["label"] if p else "default"
            prompt = f"## Active Persona: {label}\n{COMPACT_PROMPT}"
    elif persona_name == "none":
        prompt = NEUTRAL_SYSTEM_PROMPT
    else:
        preamble = build_persona_prompt(persona_name)
        if preamble:
            prompt = preamble + "\n\n" + SIYARIX_SYSTEM_PROMPT
        else:
            prompt = SIYARIX_SYSTEM_PROMPT
    return prompt
```

> [!NOTE]
> **Logic Summary at a Glance:**
> 
> | Active Setting | Initial Request | Follow-up Requests (Compact) |
> |----------------|-----------|---------------------------|
> | `none` | `NEUTRAL_SYSTEM_PROMPT` only | `COMPACT_NEUTRAL` |
> | Named (e.g., `redteam`) | Persona preamble + `SIYARIX_SYSTEM_PROMPT` | Persona label + `COMPACT_PROMPT` |
> | `universal` | Universal preamble + `SIYARIX_SYSTEM_PROMPT` | Persona label + `COMPACT_PROMPT` |
> | `auto` | Auto preamble (lists options) + `SIYARIX_SYSTEM_PROMPT` | Persona label + `COMPACT_PROMPT` |

### 📝 Persona Preamble Generation

The `build_persona_prompt()` function located in `personas.py` is responsible for generating the specific text prepended to the system prompt:

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
        for name, pp in PERSONAS.items():
            if name not in ("auto", "none"):
                lines.append(f"  - **{pp['label']}**: {pp['description']}")
        return "\n".join(lines)

    return f"## Active Persona: {p['label']}\n{p['prompt']}"
```

### 🧠 Core System Prompts

Siyarix relies on two primary system prompts, defined in `src/siyarix/chat/prompts.py`:

| Constant | Purpose | Size |
|----------|---------|------|
| `SIYARIX_SYSTEM_PROMPT` | The ultimate cybersecurity professional guide. Details operational frameworks, output formatting (JSON), tool usage steps, and communication styles. | ~60 lines |
| `NEUTRAL_SYSTEM_PROMPT` | A stripped-down assistant prompt. It omits the persona flavor but retains rules for output formats and tool execution. | ~30 lines |

> [!TIP]
> To save on token costs during longer conversations, Siyarix uses **Compact Variants** (`COMPACT_PROMPT` and `COMPACT_NEUTRAL`). These abbreviated prompts maintain the persona's context without re-sending the entire ~60-line instruction block every single time.

### 💻 Platform Context Injection

To ensure commands run smoothly on your specific machine, the prompt builder automatically injects details about your operating system via `_platform_context()`.

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
> The builder also checks your workspace for custom instruction files like `AGENTS.md` or `SOUL.md` and injects them automatically, allowing project-specific context to influence the persona!

---

## 🗄️ Persona Data Model

Personas are structured within `src/siyarix/personas.py` as a master dictionary containing all 13 modes:

```python
PERSONAS: dict[str, dict[str, Any]] = {
    "red team": {
        "name": "red team",
        "label": "Red Team / Offensive Security",
        "description": "Adversary emulation, penetration testing, exploitation, C2 operations, evasion",
        "prompt": "You are an dedicated red-team operator...",
    },
    # ... other personas like "blue team", "dfir", etc.
    "universal": { ... },    # Special: All-in-one expert
    "auto": { ... },         # Special: Smart auto-selection
    "none": { ... },         # Special: Vanilla neutral mode
}
```

### 🔍 Lookup Functions

Managing and fetching personas is handled by three straightforward functions:

```python
get_persona(name: str) -> dict | None             # Fetches a persona (case-insensitive & fuzzy)
list_personas() -> list[dict]                     # Lists all standard named personas
build_persona_prompt(name: str) -> str            # Generates the prompt text
```

> [!NOTE]  
> Persona lookups are fuzzy! `_normalize_persona_key()` strips out spaces, hyphens, and underscores. For example, typing `/persona red-team` works exactly the same as `/persona redteam`.

---

## 🎯 Example Persona: Red Team

Curious how a persona actually looks? Here is the underlying prompt for the `redteam` profile:

```python
"red team": {
    "name": "red team",
    "label": "Red Team / Offensive Security",
    "description": "Adversary emulation, penetration testing, exploitation, C2 operations, evasion",
    "prompt": (
        "You are an dedicated red-team operator who conducts realistic adversary emulation. You follow "
        "established methodologies — PTES, OSTMM, TIBER-EU — and operate across the full attack "
        "lifecycle: reconnaissance, weaponisation, delivery, exploitation, installation, C2, and "
        "exfiltration. You chain low-severity weaknesses into high-impact compromise paths, "
        "bypass modern defences (EDR, ASLR, CFG, AMSI), and maintain covert C2 with operational "
        "security. Your toolkit includes Cobalt Strike, Mythic, Sliver, BloodHound, Mimikatz, "
        "Rubeus, Certipy, Impacket, Chisel, and custom tooling. You think in assumptions of "
        "breach and test every control as if a nation-state adversary is the benchmark."
    ),
}
```

---

## ⚙️ Configuration

You don't need to restart Siyarix to change your persona. You can switch dynamically using the `/persona` command, or set a persistent default in your `settings.toml` file:

```toml
persona = "redteam"
```

> [!TIP]
> The configuration is evaluated at the start of every LLM interaction, meaning any changes you make will take effect immediately.

---

## 🔄 Integration with Interaction Modes

Personas apply to all LLM-dependent modes, such as `integrated` and `autonomous`, as well as `hybrid` mode within the `AgentCore`.

> [!WARNING]
> If you are using `registry` or `offline` modes, the persona system is bypassed entirely. In these modes, the heuristic planner operates independently, as no LLM calls are being made.

---

## 📁 Related Modules

For developers looking to tinker with or expand the system, here's where the magic happens:

| Module / Function | Path | Purpose |
|--------|------|---------|
| `PERSONAS` | `src/siyarix/personas.py` | Holds the definitions for all 10 security personas + 3 special modes. |
| `build_persona_prompt` | `src/siyarix/personas.py:218` | Assembles the text that gets injected into the prompt. |
| `SIYARIX_SYSTEM_PROMPT` | `src/siyarix/chat/prompts.py:171` | The full-spectrum base system prompt. |
| `NEUTRAL_SYSTEM_PROMPT` | `src/siyarix/chat/prompts.py:233` | The minimal base system prompt. |
| `COMPACT_PROMPT` | `src/siyarix/chat/prompts.py:263` | Token-saving variant for follow-up questions. |
| `COMPACT_NEUTRAL` | `src/siyarix/chat/prompts.py:268` | Token-saving variant for neutral mode. |
| `_build_system_prompt` | `src/siyarix/chat/engine.py:550` | The core function that stitches everything together. |
