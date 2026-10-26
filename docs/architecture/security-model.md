# 🛡️ Siyarix Security Model

!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Siyarix implements a robust, defense-in-depth security model designed to protect your data, enforce operational security (OPSEC), and ensure safe execution at all times. Our architecture spans multiple critical layers—from input validation and permission gating to stealth operations and tamper-evident auditing. Each layer is independently configurable, allowing you to combine them for graduated, context-aware safety policies.

!!! note
    The security model is built on the principle of least privilege and zero-trust execution. Every action is verified, sanitized, and audited before it touches your system or the outside world.

---

## 🏗️ Security Layers Overview

Here's how a request flows through the Siyarix security pipeline:

```text
┌─────────────────────────────────────────────────────────────┐
│                      User Input                             │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 🔍 Layer 1: Input Validation                        │    │
│  │  • Length limits     • Null bytes                   │    │
│  │  • Shell injection   • Target format                │    │
│  │  • Tool presence     • Timeout checks               │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 🚦 Layer 2: Permission Gate                         │    │
│  │  • Plan validation (allow/review/block)             │    │
│  │  • 38+ danger signatures                            │    │
│  │  • Target scope checking                            │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 🕵️ Layer 3: DLP Engine                              │    │
│  │  • Data leak prevention & pattern matching          │    │
│  │  • 24+ detection signatures                         │    │
│  │  • Automatic redaction                              │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 🎭 Layer 4: OPSEC Manager                           │    │
│  │  • memory_only (in-process; suppresses audit/cache) │    │
│  │  • Session burn: local file shred (3-pass)          │    │
│  │  • Tor / DoH / MAC / OS netns: Planned              │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 🥷 Layer 5: Stealth Engine                          │    │
│  │  • Evasion levels (none/light/medium/heavy/paranoid)│    │
│  │  • User-Agent rotation & request jitter (implemented)│   │
│  │  • Proxy/decoy flags: config markers (verify locally)│   │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 🔧 Layer 6: Tool Call Repair                        │    │
│  │  • Malformed LLM tool call correction               │    │
│  │  • Parameter normalization & schema recreation      │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 📦 Layer 7: Execution (Sandboxed)                   │    │
│  │  • Tool-level sandboxing & command isolation        │    │
│  │  • Timeout & resource limits                        │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 🔐 Layer 8: Audit & Credential Management           │    │
│  │  • Tamper-evident SHA-256 audit chain               │    │
│  │  • Encrypted CredentialStore                        │    │
│  └─────────────────────────────────────────────────────┘    │
│                            │                                │
│                     ⚡ Execution                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Layer 1: Input Validation (Validators)

Before any plan is even considered for execution, the **Validator** class (`siyarix/validators.py`) steps in to ensure everything is structurally sound and safe.

### Validation Checks

| Check | Purpose |
|-------|---------|
| **Length limits** | Rejects overly long commands (>5000 chars) to prevent buffer overflows or denial of service. |
| **Null bytes** | Blocks commands containing `\0` or `%00` often used in bypass attacks. |
| **Shell injection** | Detects and stops dangerous characters like `;`, `|`, `$(...)`, backticks, `&&`, and `||`. |
| **Target format** | Validates the syntax of IP ranges, domains, and URLs. |
| **Tool presence** | Ensures the requested tool actually exists in the `ToolRegistry`. |
| **Timeout limits** | Prevents endless loops by rejecting steps with no timeout or excessively long ones. |
| **Argument safety** | Verifies all required arguments are present and blocks unrecognized parameters. |

!!! tip "Automatic Recovery"
    If validation fails, Siyarix doesn't just give up. It attempts to apply a recovery action—like retrying (`RETRY`), fixing parameters (`RETRY_MODIFIED`), switching tools (`RETRY_ALTERNATIVE`), or escalating to the user (`ESCALATE`).

---

## 🚦 Layer 2: Permission Gate

The Permission Gate (`siyarix/permission_gate.py`) is your automated security guard. It evaluates every planned step against strict safety policies to determine if it should proceed.

### Gate Levels

| Level | Behavior | Ideal Use Case |
|-------|----------|----------------|
| 🟢 `ALLOW` | Proceeds without interrupting you. | Safe, read-only operations (e.g., fetching a file). |
| 🟡 `REVIEW` | Requires your explicit confirmation. | Destructive, modifying, or highly sensitive actions. |
| 🔴 `BLOCK` | Permanently denied and logged. | Extremely dangerous or out-of-scope actions. |

### 🚨 Danger Signatures

The gate comes pre-loaded with **38+ danger signatures** to catch risky behavior:

- **Destructive:** `rm -rf`, disk wipes, `dd`, `format`
- **Privilege Escalation:** `sudo`, `su`, `chmod 777`
- **Exfiltration:** Unauthorized external data transfers, DNS tunneling
- **Persistence:** Modifications to cron jobs or startup scripts
- **Obfuscation:** Encoded payloads, reverse shells

---

## 🕵️ Layer 3: DLP Engine (Data Leak Prevention)

Your secrets are safe with Siyarix. The DLP engine (`siyarix/dlp.py`) actively scans data *before* it gets sent to LLMs or third-party APIs.

### Detection Signatures

With **24+ built-in signatures**, the DLP engine catches things like:
- **API Keys & Tokens:** `sk-...`, `Bearer ...`, AWS keys
- **Passwords & SSH Keys:** `password=...`, PEM-encoded private-key headers (example pattern only)
- **PII:** Emails, SSNs, credit cards
- **Internal Infrastructure:** RFC1918 internal IP addresses

!!! warning
    By default, the DLP engine is set to `REDACT`, meaning it will automatically mask sensitive strings (e.g., swapping an API key with `[REDACTED]`).

**Configuration Example:**
```toml
[dlp]
enabled = true
mode = "redact"           # Options: redact | warn | block | escalate
sensitivity = "high"      # Options: low | medium | high
custom_patterns = [
    "CUSTOM-TOKEN-\\w{16}",
]
```

---

## 🎭 Layer 4: OPSEC Manager

The **OPSECManager** (`siyarix/opsec.py`) applies **in-process** operational controls. It does **not** create OS network namespaces, Tor circuits, DoH resolvers, or MAC randomization today.

### Implemented

| Control | Behavior |
|---------|----------|
| **`memory_only`** | Suppresses persistent audit/cache writes for the session. Emits a loud accountability warning — the tamper-evident trail is **not** attestatable while active. |
| **Soft session label** | Namespaced string marker only; `isolated` stays `False` (no OS netns). |
| **`burn()`** | 3-pass random overwrite of local session files under the config log dir. OS memory/swap/pagefile/network wipe is **`not_implemented`**; burn returns **partial** status. |

### Planned / not implemented

| Control | Status |
|---------|--------|
| OS network namespace isolation | Planned — `isolate()` refuses success when implied |
| Tor routing | Planned — requesting `use_tor=True` → `success=False` |
| DNS-over-HTTPS (DoH) | Planned — requesting `use_doh=True` → `success=False` |
| MAC address randomization | Planned — requesting `randomize_mac=True` → `success=False` |

!!! warning "Accountability tradeoff"
    Enabling `memory_only` deliberately discards unflushed audit events. Use only when you accept loss of session attestability.

---

## 🥷 Layer 5: Stealth Engine

The **StealthEngine** (`siyarix/stealth.py`) configures evasion **levels** (string keys, not numeric 0–4). **User-Agent rotation** and **request jitter** are implemented in-process. Proxy-chain and decoy flags set configuration markers (default proxy list points at localhost listeners such as `127.0.0.1:9050` / `8118`) — they are **not** OS-level Tor/MAC/DNS-tunnel isolation.

| Level | Jitter % | UA rotation | Proxy-chain flag | Decoy-traffic flag |
|-------|----------|-------------|------------------|--------------------|
| **none** | 0 | No | No | No |
| **light** | 10 | Yes | No | No |
| **medium** | 30 | Yes | Yes | No |
| **heavy** | 50 | Yes | Yes | Yes |
| **paranoid** | 80 | Yes | Yes | Yes |

!!! note "Honesty"
    Advanced network OPSEC (real Tor routing, MAC rotation, DNS tunneling, C2 mimicry) is **not** implemented by OPSECManager or StealthEngine. Treat proxy injection as optional local config — verify your listener before relying on it.

---

## 🔧 Layer 6: Tool Call Repair

LLMs are brilliant, but sometimes they output malformed JSON or use the wrong data types. The **ToolCallRepair** system (`siyarix/tool_call_repair.py`) acts as a smart middleware to fix these issues on the fly.

- **Missing parameters?** It injects safe defaults.
- **Wrong types?** It automatically coerces them (e.g., converting a list to a comma-separated string).
- **Hallucinated tool names?** It uses fuzzy matching to find the closest valid tool.

This ensures the Execution layer only ever receives syntactically perfect commands.

---

## 📦 Layer 7: Execution Sandboxing

When a tool is finally cleared to run, it executes in a tightly controlled environment.

- **Command Isolation:** Tools run in a subprocess isolated from the core application.
- **Resource Limits:** Memory and output sizes are capped to prevent crashes.
- **Temporary Workspaces:** Operations run in a sandboxed temporary directory.
- **Network Scope Enforcement:** Network requests are checked against your approved scope—any attempts to reach out-of-scope targets are dropped.

---

## 🔐 Layer 8: Audit & Credential Management

Transparency and safe credential handling are fundamental.

### 📜 Tamper-Evident Audit Log

The `AuditLogger` (`siyarix/audit.py`) builds a cryptographic chain of every action taken.

```python
# Conceptual Audit Entry
entry = {
    "timestamp": "2026-06-25T12:00:00Z",
    "action": "execute_tool",
    "status": "completed",
    "hash": "sha256_of_previous_entry_hash + content",
    "previous_hash": "a1b2c3d4...",
}
```

!!! note
    Because each entry hashes the previous one, the audit log is **tamper-evident**. Modifying a past entry will break the entire cryptographic chain, instantly alerting you to foul play.

### 🔑 CredentialStore

Passwords and tokens are managed securely via `siyarix/credential_store.py`:
- **Encryption:** Uses Fernet symmetric encryption.
- **Master Key:** Derived from your master password via PBKDF2.
- **Usage:** API keys are injected directly into environment variables at runtime, never written to plaintext logs.

---

## 🛠️ Security Commands

Manage your security posture directly from the CLI (`siyarix/security_commands.py`):

```bash
siyarix security audit-log          # View the audit trail
siyarix security verify-chain       # Verify audit chain integrity
siyarix security credential-store   # Manage the encrypted store
siyarix security permissions        # Tweak permission policies
siyarix security scope              # Manage operational boundaries
siyarix security session-list       # View active sessions
```

---

## 👾 Threat Model & Mitigations

We've anticipated major attack vectors and built specific countermeasures:

| Threat | Mitigation Layer | Severity |
|--------|-----------------|----------|
| **Prompt Injection** | Layer 1: Validators (shell inject/length checks) | High |
| **Destructive AI Commands**| Layer 2: Permission Gate (38+ signatures) | High |
| **Data Leaks to AI** | Layer 3: DLP Engine (pattern redaction) | Critical |
| **Operator OPSEC Leak** | Layer 4: `memory_only` + burn file shred; Layer 5: UA/jitter (Tor/DoH/MAC Planned) | Medium |
| **Defensive Detection** | Layer 5: Stealth Engine (evasion tiers) | Medium |
| **Malformed AI Output** | Layer 6: Tool Call Repair | Medium |
| **Log Tampering** | Layer 8: SHA-256 Cryptographic Chain | Critical |
| **Credential Theft** | Layer 8: Encrypted CredentialStore | High |
| **Scope Creep** | Layer 2 & 7: Target Scope Enforcement | High |

---

## ⚙️ Safety Policy Quick Reference

You can quickly toggle the overall safety posture using the `SIYARIX_SAFE_MODE` environment variable:

| Mode | Permission Gate | DLP Engine | OPSEC (`memory_only`) | Stealth level |
|-------|----------------|------------|----------------------|---------------|
| **`strict`** (Default) | ALLOW / REVIEW / BLOCK | REDACT | Off by default (operator opt-in) | light |
| **`permissive`** | ALLOW / REVIEW | WARN | Off | none |
