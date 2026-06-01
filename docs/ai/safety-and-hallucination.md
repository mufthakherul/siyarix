# Safety & Hallucination Handling

Siyarix implements multiple safeguards to prevent AI hallucination, dangerous command generation, and output fabrication.

## Command safety (`security_hardening.py`)

### Danger analysis

38 dangerous command patterns are checked before any execution:

| Category | Patterns |
|----------|----------|
| System destruction | `dd`, `mkfs`, `format`, `mkswap`, `parted`, `fdisk destructive` |
| Recursive deletion | `rm -rf /`, `rm -rf ~`, `rm -rf .`, `rm -rf /*` |
| File truncation | `> /dev/sda`, `:() { :\|:& };:`, `fork bomb` |
| Network abuse | `ping -f`, `ping flood`, `hping3 flood`, `slowloris` |
| Priv escalation | `sudo !!`, `chown 0`, `chmod 0`, `su -` |
| Data destruction | `shred -z`, `wipe`, `srm`, `sfill` |

### Danger levels

| Level | Action |
|-------|--------|
| `ALLOW` | Command passes, executes immediately |
| `FLAG` | Command flagged for user confirmation |
| `DENY` | Command blocked, logged, not executed |

### Input validation (`security_hardening.py::InputValidator`)

Pre-execution validation:

- Length limits on commands and arguments
- Reject null bytes and control characters
- Validate target format (IP, CIDR, hostname, URL)
- Shell injection pattern detection (`;`, `|`, `` ` ``, `$()`)

## Data redaction (`security_hardening.py::SecretRedactor`)

24 regex patterns automatically redact secrets from output:

- `-----BEGIN RSA PRIVATE KEY-----`
- `sk-...` (OpenAI keys)
- `AKIA...` (AWS access keys)
- `ghp_...` (GitHub tokens)
- JWT tokens (`eyJ...`)
- Bearer tokens
- Database URLs (`postgres://user:pass@...`)

## Safe mode

Activated via env var or config:

```bash
export SIYARIX_SAFE_MODE=1
```

In safe mode:

- All destructive commands are denied
- Only reconnaissance and scanning permitted
- Permission gate enforces maximum strictness
- Emergency stop via Ctrl+C

## Emergency stop

All running commands can be stopped immediately:

- Press **Ctrl+C** once to cancel the current task
- Press **Ctrl+C** twice to exit Siyarix entirely
- The execution engine halts all subprocesses and cleans up
- Logs the stop event to audit trail
- Cannot be re-armed without explicit user action

## OPSEC controls (`opsec.py`)

Operational security during assessment:

- **TOR routing**: Anonymize outbound connections
- **DNS over HTTPS**: Prevent DNS-based tracking
- **Request jitter**: Random delays between connections
- **User-Agent rotation**: Mimic different browsers
- **Session burning**: Securely wipe session artifacts

## Ethical constraints

The system enforces ethical boundaries:

- No commands targeting systems without explicit authorization
- No denial-of-service commands (flood, stress testing)
- No social engineering tool generation
- All operations must comply with local laws

## Audit trail

Every safety event is logged:

```json
{
  "timestamp": "2026-05-28T10:30:00Z",
  "event_type": "SAFETY_BLOCK",
  "command": "nmap --script http-slowloris target",
  "reason": "Pattern match: network flooding",
  "action": "DENY",
  "persona": "defensive"
}
```

The audit log uses SHA-256 chaining for tamper evidence.
