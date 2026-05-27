# Safety & Hallucination Handling

Siyarix implements multiple safeguards to prevent AI hallucination, dangerous command generation, and output fabrication.

## Hallucination detection (`response_sensor.py`)

The `ResponseSensor` validates AI outputs before execution:

### Confidence scoring

Each AI response is scored on:

- **Structure compliance**: Does the response match expected JSON format?
- **Tool existence**: Does the proposed tool exist in the registry?
- **Command plausibility**: Is the command well-formed and realistic?
- **Target validity**: Does the target match expected patterns (IP, hostname, URL)?

### Cross-validation

The sensor cross-references AI output against:

```python
# Example validation
if response.get("tool") not in registry.list_tools():
    return ValidationResult.FAIL("Tool not found in registry")

if not validate_target(response.get("target", "")):
    return ValidationResult.FAIL("Invalid target format")
```

### Fallback for low confidence

When confidence is below threshold:

1. The AI result is rejected
2. Heuristic routing (`RuleInterpreter`) is used instead
3. The user is notified of the fallback

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

## Persona-based safety

Each persona defines allowed operations:

```python
persona = persona_engine.get("defensive")
# ACL: scan tools only, no exploit, no shell commands
```

## Safe mode

Activated via env var or config:

```bash
export SIYARIX_SAFE_MODE=1
```

In safe mode:

- All destructive commands are denied
- Only reconnaissance and scanning permitted
- Permission gate enforces maximum strictness
- Kill switch pre-armed

## Kill switch (`kill_switch.py`)

Emergency stop for autonomous operations:

```
States: ARMED → TRIGGERED → DISARMED
```

Triggering the kill switch:

- Immediately halts all execution
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
