# Abuse Prevention

Siyarix implements multiple layers of abuse prevention to stop malicious or accidental misuse.

## Prevention layers

```
┌─────────────────────────────────────────┐
│    Command-level prevention             │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │  Danger  │  │  Syntax  │  │ ACL │ │
│  │ Analysis │  │  Check   │  │ Gate│ │
│  └──────────┘  └──────────┘  └──────┘ │
├─────────────────────────────────────────┤
│    System-level prevention              │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │Kill Sw.  │  │ Safe     │  │OPSEC│ │
│  │(emer-    │  │ Mode     │  │Evade│ │
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

Three-stage gate per command:

```
Command → Syntax Check → Danger Analysis → Persona ACL → Result
```

Each stage returns `ALLOW`, `FLAG`, or `DENY`.

## 3. Kill switch

Emergency stop mechanism:

```python
kill_switch = KillSwitch()
kill_switch.arm()

# On dangerous condition:
kill_switch.trigger()
# All execution halts, state is logged
```

States:

| State | Behavior |
|-------|----------|
| `ARMED` | System running, kill switch can be triggered |
| `TRIGGERED` | All execution stopped, requires explicit disarm |
| `DISARMED` | Normal operation (cannot re-arm without restart) |

## 4. Safe mode

```bash
export SIYARIX_SAFE_MODE=1
```

Restricts all operations to reconnaissance only:

- Scanning tools only (nmap, masscan, nuclei passive)
- No exploitation (metasploit, sqlmap active)
- No destructive commands (dd, rm, format)
- Permission gate at maximum strictness
- Kill switch pre-armed on startup

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

Auto-redact 24 secret patterns from all output:

```python
PATTERNS = [
    r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    r"sk-[a-zA-Z0-9]{20,}",      # OpenAI keys
    r"AKIA[0-9A-Z]{16}",          # AWS access keys
    r"ghp_[a-zA-Z0-9]{36}",       # GitHub tokens
    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",  # JWTs
]
```

## 7. Audit trail

All safety events are logged to the tamper-evident audit log:

| Event | Logged data |
|-------|-------------|
| Command blocked | command, reason, pattern matched |
| Kill switch triggered | trigger reason, timestamp |
| Safe mode violation | command, persona, target |
| Permission gate | gate stage, result, user action |

## 8. Persona-based restrictions

Each persona has an ACL that restricts tool access:

| Persona | Permitted | Blocked |
|---------|-----------|---------|
| `defensive` | nmap, nuclei (passive), nikto | metasploit, sqlmap, hydra |
| `soc_analyst` | Monitoring tools only | All exploitation, scanning limited |
| `offensive` | All tools | Nothing |
| `pentester` | All standard tools | Destructive system commands |
| `bug_hunter` | Vuln scanners only | Exploitation |
