# Abuse Prevention

Siyarix implements multiple layers of abuse prevention to stop malicious or accidental misuse.

## Prevention layers

```
┌─────────────────────────────────────────┐
│    Command-level prevention             │
│  ┌──────────┐  ┌──────────┐            │
│  │  Danger  │  │  Syntax  │            │
│  │ Analysis │  │  Check   │            │
│  └──────────┘  └──────────┘            │
├─────────────────────────────────────────┤
│    System-level prevention              │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │Kill Sw.  │  │ Safe     │  │OPSEC │ │
│  │(emer-    │  │ Mode     │  │Evade │ │
│  │ gency)   │  │          │  │     │ │
│  └──────────┘  └──────────┘  └──────┘ │
├─────────────────────────────────────────┤
│    Audit-level prevention              │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │Audit Log │  │ Session  │  │SIEM  │ │
│  │(chain)   │  │   Log    │  │Fwd   │ │
│  └──────────┘  └──────────┘  └──────┘ │
└─────────────────────────────────────────┘
```

## 1. Danger analysis

38 dangerous command patterns are checked pre-execution:

```python
PATTERNS = {
    "destructive_disk": r"\b(dd|mkfs|format|mkswap|parted)\b.*(if=|/dev/)",
    "recursive_delete": r"\brm\b.*\s(-rf|/\s*\*)",
    "network_flood": r"\b(ping|hping3|nping)\b.*(-f|--flood)",
    "fork_bomb": r":\(\)\s*\{.*:\|:&\};:",
    "priv_escalation": r"\bsudo\b.*(\!\!|su\s*-)",
}
```

## 2. Permission gate

Two-stage gate per command:

```
Command → Syntax Check → Danger Analysis → Result
```

Each stage returns `ALLOW`, `FLAG`, or `DENY`.

## 3. Emergency stop

- Press **Ctrl+C** once to cancel the current task
- Press **Ctrl+C** twice to exit Siyarix entirely
- The execution engine halts all subprocesses and cleans up

## 4. Safe mode

```bash
export SIYARIX_SAFE_MODE=1
```

Restricts to reconnaissance only:
- Scanning tools only (nmap, masscan, nuclei passive)
- No exploitation (metasploit, sqlmap active)
- No destructive commands (dd, rm, format)
- Permission gate at maximum strictness

## 5. OPSEC controls

`opsec.py` implements operational security:

| Control | Description |
|---------|-------------|
| TOR routing | Route all outbound traffic through TOR |
| DNS over HTTPS | Prevent DNS leakage |
| Session burning | Secure cleanup of artifacts |
| Request jitter | Random delays between connections |
| Proxy rotation | Rotate through proxy pool |

## 6. Secret redaction

Auto-redacts 24 secret patterns from all output:

```python
PATTERNS = [
    r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    r"sk-[a-zA-Z0-9]{20,}",          # OpenAI keys
    r"AKIA[0-9A-Z]{16}",             # AWS access keys
    r"ghp_[a-zA-Z0-9]{36}",          # GitHub tokens
    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",  # JWTs
]
```

## 7. Audit trail

All safety events are logged to the tamper-evident audit log:

| Event | Logged data |
|-------|-------------|
| Command blocked | command, reason, pattern matched |
| Emergency stop | trigger reason, timestamp |
| Safe mode violation | command, persona, target |
| Permission gate | gate stage, result, user action |
