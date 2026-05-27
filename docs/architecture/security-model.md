# Security Model

Siyarix implements defense-in-depth with multiple security layers controlling command execution, data handling, and system access.

## Security layers

```
┌─────────────────────────────────────────┐
│          Permission Gate                │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │  Syntax  │→│  Danger  │→│ ACL │ │
│  │  Check   │  │ Analysis │  │     │ │
│  └──────────┘  └──────────┘  └──────┘ │
├─────────────────────────────────────────┤
│         Data Protection                 │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │ Masking  │  │Credential│  │Secret│ │
│  │ Engine   │  │  Store   │  │Rdrctr│ │
│  └──────────┘  └──────────┘  └──────┘ │
├─────────────────────────────────────────┤
│          Audit & Controls               │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │Audit Log │  │ Kill Sw. │  │OPSEC │ │
│  │(tamper-  │  │ (emer-   │  │(TOR, │ │
│  │ evident) │  │ gency)   │  │ DoH) │ │
│  └──────────┘  └──────────┘  └──────┘ │
└─────────────────────────────────────────┘
```

## 1. Permission gate (`permission_gate.py`)

Three stages, evaluated in order:

### Stage 1: Syntax check

Validates command structure before any execution:

- Length limits
- Character restrictions
- Shell injection pattern detection
- Malformed command rejection

### Stage 2: Danger analysis

Pattern-matches against 38 dangerous command signatures:

| Pattern | Example | Action |
|---------|---------|--------|
| Destructive disk ops | `dd`, `format`, `mkfs` | DENY |
| Recursive deletion | `rm -rf /`, `rm -rf ~` | DENY |
| System modification | `chmod 0 /`, `mknod` | DENY |
| Network flooding | `ping -f`, `hping3 --flood` | FLAG |
| Privilege escalation | `sudo !!`, `su -` | FLAG |
| Data exfiltration | `nc -e`, `curl --data @/etc` | FLAG |

### Stage 3: Persona ACL

Each persona (`PersonaEngine`) defines a tool ACL:

- **offensive**: Full access, all tools
- **pentester**: Standard tools, suspicious patterns flagged
- **defensive**: Scan-only, no exploitation tools
- **soc_analyst**: Read-only tools, monitoring only
- **bug_hunter**: Vulnerability detection only

Commands failing any stage return `DENY` or `FLAG` (user confirmation required).

## 2. Data protection

### Masking engine (`masking.py`)

Bidirectional token masking protects sensitive data sent to AI providers:

- Credentials → `[REDACTED]` (permanent, irreversible)
- API keys → `[REDACTED]` (permanent, irreversible)
- IP addresses → `10.x.x.x` (reversible within session)
- Internal hostnames → `example.com` (reversible within session)
- JWTs → `[REDACTED]` (permanent, irreversible)

### Credential store (`credential_store.py`)

Encrypted vault for API keys and secrets:

- **Encryption**: AES-256-GCM with key rotation support
- **Key storage**: System keyring via `keyring` library
- **Optional KMS**: AWS KMS envelope encryption
- **Auto-clear**: Session end cleanup

### Secret redactor (`security_hardening.py`)

24 regex patterns for automatic secret detection in output:

- AWS keys, SSH keys, JWT tokens, API keys
- Database connection strings
- OAuth tokens, bearer tokens
- Private keys (RSA, EC, Ed25519)

## 3. Audit & controls

### Audit log (`audit_log.py`)

Tamper-evident log with SHA-256 hash chain:

- Every command is logged with session ID
- Each entry contains SHA-256 of the previous entry
- Entries cannot be modified without breaking the chain
- SIEM forwarding (Splunk, ELK, Azure Sentinel)

### Kill switch (`kill_switch.py`)

Emergency stop mechanism:

- States: ARMED → TRIGGERED → DISARMED
- Callback-based notification on trigger
- Can be integrated with monitoring systems

### OPSEC (`opsec.py`)

Operational security controls:

- **TOR routing**: Route traffic through TOR for anonymity
- **DNS over HTTPS**: Prevent DNS leakage
- **Session burning**: Secure cleanup of session artifacts
- **Traffic jitter**: Random delays between requests
- **User-Agent rotation**: Rotate HTTP fingerprints

## Safe mode

Enable safe mode to prevent all destructive actions:

```bash
export SIYARIX_SAFE_MODE=1
siyarix ...
```

In safe mode:
- All exploitation commands are blocked
- Only reconnaissance and scanning tools are allowed
- Permission gate enforces stricter rules
- Kill switch is pre-armed
