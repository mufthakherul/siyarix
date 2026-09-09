# 🛡️ Abuse Prevention

Siyarix is a powerful tool, and I want to make sure it's used safely. To help prevent accidental damage or misuse, I've built in some layers of abuse prevention. These layers operate to try to catch mistakes and keep things reasonable.

## 🍰 The Layers of Prevention

Think of it like a multi-layered cake:

```text
┌─────────────────────────────────────────┐
│        Command-Level Prevention         │
│  ┌──────────┐            ┌──────────┐   │
│  │  Danger  │            │  Syntax  │   │
│  │ Analysis │            │  Check   │   │
│  └──────────┘            └──────────┘   │
├─────────────────────────────────────────┤
│        System-Level Prevention          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │Kill Sw.  │ │   Safe   │ │  OPSEC   │ │
│  │(emer-    │ │   Mode   │ │  Evade   │ │
│  │ gency)   │ │          │ │          │ │
│  └──────────┘ └──────────┘ └──────────┘ │
├─────────────────────────────────────────┤
│        Audit-Level Prevention           │
│  ┌──────────┐ ┌──────────┐              │
│  │Audit Log │ │ Session  │              │
│  │(chain)   │ │   Log    │              │
│  └──────────┘ └──────────┘              │
└─────────────────────────────────────────┘
```

!!! tip
    These layers mostly operate automatically, so you don't need to configure much out of the box.

## 1. 🛑 Danger Analysis

Before a command runs, `permission_gate.py` checks it against some common dangerous patterns.

```python
PATTERNS = {
    "destructive_disk": r"\b(dd|mkfs|format|mkswap|parted)\b.*(if=|/dev/)",
    "recursive_delete": r"\brm\b.*\s(-rf|/\s*\*)",
    "network_flood": r"\b(ping|hping3|nping)\b.*(-f|--flood)",
    "fork_bomb": r":\(\)\s*\{.*:\|:&\};:",
    "priv_escalation": r"\bsudo\b.*(\!\!|su\s*-)",
}
```

It blocks things like accidental disk formatting or recursive file deletion.

## 2. 🚧 The Permission Gate

Commands go through a review process:

`Command → Syntax Gate → Danger Analysis → Result`

The gate returns `ALLOW`, `FLAG` (asking you), or `DENY`.

## 3. 🤐 Data Loss Prevention (DLP) Engine

To help avoid accidentally sending your local secrets to cloud AI providers, the `dlp.py` engine tries to mask basic patterns (like SSH keys or AWS keys) locally before the prompt is sent.

!!! info
    The DLP is a helpful safety net, but always be careful what you type into chat prompts!

## 4. 🚨 Emergency Stop (Kill Switch)

If things get out of hand:
- **Press `Ctrl+C` once:** Cancels the current task.
- **Press `Ctrl+C` twice:** Halts Siyarix completely.

## 5. 🦺 Safe Mode

If you just want to run passive tools:

```bash
export SIYARIX_SAFE_MODE=1
```

**In Safe Mode:**
- Only reconnaissance is allowed.
- Destructive commands are blocked.
- The Permission Gate is stricter.

## 6. 🥷 OPSEC Controls

Siyarix has some built-in evasion controls via `opsec.py` for testing, such as TOR routing or jittered requests.

## 7. 🔒 System-Level Security Hardening

For advanced setups, `security_hardening.py` adds basic OS protections like checking for excessive permissions.

## 8. 📜 The Audit Trail

Transparency is key. Safety events are logged in an audit log.

| Event Type | What gets logged |
|-------|-------------|
| **Blocked Command** | The command and the matched pattern. |
| **Emergency Stop** | The trigger reason and timestamp. |
| **Safe Mode Violation** | The attempted command. |
| **DLP Redaction** | The *type* of pattern redacted, but never the actual secret. |
