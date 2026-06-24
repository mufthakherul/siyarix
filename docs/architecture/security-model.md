# Security Model

Siyarix implements a defense-in-depth security model spanning input validation, permission gating, data loss prevention, opsec enforcement, stealth operations, tool call repair, tamper-evident auditing, credential management, and sandboxed execution. Each layer is independently configurable and can be combined for graduated safety policies.

---

## Security Layers Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      User Input                             │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 1: Input Validation (Validators)              │   │
│  │  • Length limits     • Null bytes                   │   │
│  │  • Shell injection   • Target format                │   │
│  │  • Tool presence     • Timeout checks               │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 2: Permission Gate                            │   │
│  │  • Plan validation (allow/review/block)             │   │
│  │  • 38+ danger signatures                            │   │
│  │  • Target scope checking                            │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 3: DLP Engine                                 │   │
│  │  • Data leak prevention pattern matching            │   │
│  │  • 24+ detection signatures                         │   │
│  │  • Automatic redaction                              │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 4: OPSEC Manager                             │   │
│  │  • Operational security enforcement                 │   │
│  │  • Source IP rotation                               │   │
│  │  • DNS over HTTPS                                   │   │
│  │  • User-Agent rotation                              │   │
│  │  • Timing jitter                                    │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 5: Stealth Engine                             │   │
│  │  • Stealth level tiers (0-4)                        │   │
│  │  • Evasion techniques                               │   │
│  │  • Safe commands                                    │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 6: Tool Call Repair                           │   │
│  │  • Malformed LLM tool call correction               │   │
│  │  • Parameter normalization                          │   │
│  │  • Schema reconstruction                            │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 7: Execution (Sandboxed)                      │   │
│  │  • Tool-level sandboxing                            │   │
│  │  • Command isolation                                │   │
│  │  • Timeout enforcement                              │   │
│  │  • Resource limits                                  │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 8: Audit & Credential Management              │   │
│  │  • Tamper-evident SHA-256 audit chain               │   │
│  │  • CredentialStore with encryption                  │   │
│  │  • Provider credentials via environment/encrypted   │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                      Execution                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Input Validation (Validators)

The **Validator** class in `siyarix/validators.py` provides plan-level validation before execution:

### Validation Checks

| Check | Purpose |
|-------|---------|
| **Length limits** | Reject steps with overly long commands (>5000 chars) |
| **Null bytes** | Reject commands containing `\0` or `%00` |
| **Shell injection** | Detect `;`, `|`, `$(...)`, backtick, `&&`, `||` patterns |
| **Target format** | Validate IP ranges, domains, and URLs |
| **Tool presence** | Ensure referenced tool exists in ToolRegistry |
| **Timeout limits** | Reject steps with no timeout or excessive timeout |
| **Argument safety** | Verify all required args present, no unknown args |

### Recovery Actions

When validation fails, the system applies a recovery action:

| Action | Behavior |
|--------|----------|
| `RETRY` | Re-execute same step (for transient failures) |
| `RETRY_ALTERNATIVE` | Execute alternative tool/approach |
| `RETRY_MODIFIED` | Fix and re-execute with corrected params |
| `SKIP` | Skip this step, continue with next |
| `ABORT` | Abort entire plan |
| `ESCALATE` | Escalate to user/admin |
| `DEGRADE` | Continue with reduced functionality |
| `WAIT` | Wait and retry after delay |

```python
validator = Validator(timeout=TIMEOUT)
# Validate entire plan
validations = validator.validate_plan(plan)
# Generate recovery actions
recoveries = [validator.plan_recovery(v) for v in validations if not v.is_valid]
```

---

## Layer 2: Permission Gate

The permission gate in `siyarix/permission_gate.py` evaluates planned steps against safety policies:

### Gate Levels

| Level | Behavior | Use Case |
|-------|----------|----------|
| `ALLOW` | Proceeds without user input | Safe, read-only operations |
| `REVIEW` | Requires explicit user confirmation | Destructive or sensitive actions |
| `BLOCK` | Permanently denied and logged | Dangerous or out-of-scope actions |

### Danger Signatures

The gate maintains 38+ signatures for pattern detection:

| Category | Examples |
|----------|---------|
| **Destructive** | `rm -rf`, `dd`, `format`, `mkfs`, disk wipe |
| **Recon (internal)** | `arp -a`, local credential dumping, network config |
| **Exfiltration** | External data transfer, DNS tunneling |
| **Privilege escalation** | `sudo`, `su`, `chmod 777`, `setuid` |
| **Persistence** | Cron jobs, startup scripts, services |
| **Obfuscation** | Encoded commands, reverse shells, tunneling |

---

## Layer 3: DLP Engine

The DLP (Data Leak Prevention) engine in `siyarix/dlp.py` prevents sensitive data from being sent to AI providers:

### Detection Signatures

24+ signatures for common sensitive data patterns:

| Pattern | Example Matches |
|---------|----------------|
| **API Keys** | `sk-...`, `pk-...`, `ghp_...`, `AKIA...` |
| **Passwords** | `password=...`, `passwd: ...`, `P@ssw0rd` |
| **Tokens** | `Bearer ...`, `JWT ...`, `xoxb-...`, `xoxp-...` |
| **SSH Keys** | `-----BEGIN RSA PRIVATE KEY-----` |
| **Certificates** | `-----BEGIN CERTIFICATE-----` |
| **Connection strings** | `Server=...;Database=...;Uid=...` |
| **Cloud credentials** | AWS, Azure, GCP key formats |
| **PII** | Email, SSN, phone, credit card |
| **Internal IPs** | RFC1918 addresses (10.x, 172.16-31.x, 192.168.x) |

### DLP Actions

| Action | Behavior |
|--------|----------|
| `REDACT` | Replace matching pattern with `[REDACTED]` |
| `WARN` | Log warning but allow through |
| `BLOCK` | Block content from being sent to provider |
| `ESCALATE` | Notify security admin |

### Configuration

```toml
[dlp]
enabled = true
mode = "redact"           # redact | warn | block | escalate
sensitivity = "high"      # low | medium | high
custom_patterns = [
    "CUSTOM-TOKEN-\\w{16}",
]
```

---

## Layer 4: OPSEC Manager

The **OPSECManager** in `siyarix/opsec.py` enforces operational security during execution:

### Features

| Feature | Description |
|---------|-------------|
| **Source IP rotation** | Cycles through configured source IPs/proxies |
| **DNS over HTTPS** | Resolves DNS via DoH to avoid DNS monitoring |
| **User-Agent rotation** | Randomizes User-Agent headers per request |
| **Timing jitter** | Adds random delays (configurable jitter) between operations |
| **Proxy rotation** | Cycles through proxy list |

```python
opsec = OPSECManager(
    proxy_list=["socks5://127.0.0.1:9050", "http://proxy2:8080"],
    user_agents=["Mozilla/5.0 ...", "curl/8.0 ..."],
    jitter_range=(1.0, 5.0),
    enable_doh=True,
    rotate_interval=60,
)
```

### OPSEC Levels

| Level | Proxy | DoH | Jitter | UA Rotation |
|-------|-------|-----|--------|-------------|
| `OFF` | No | No | 0s | No |
| `LOW` | No | Yes | 0.5–2s | Per session |
| `MEDIUM` | Optional | Yes | 1–5s | Per request |
| `HIGH` | Required | Yes | 2–10s | Per request |

---

## Layer 5: Stealth Engine

The **StealthEngine** in `siyarix/stealth.py` provides evasion controls for operations requiring minimal detection:

### Stealth Tiers

| Tier | Name | Behavior |
|------|------|----------|
| `0` | **None** | No evasion; standard execution |
| `1` | **Light** | Rate limiting, polite scanning |
| `2` | **Medium** | Decoy traffic, randomized delays, User-Agent rotation |
| `3` | **High** | Proxy chaining, traffic obfuscation, timing normalization |
| `4` | **Paranoid** | Full evasion: Tor, MAC rotation, DNS tunneling, C2 mimicry |

### Safe Commands

The Stealth Engine maintains a list of commands that are considered "safe" at each tier level. Commands exceeding the tier's safe threshold trigger warnings or blocks.

---

## Layer 6: Tool Call Repair

The **ToolCallRepair** in `siyarix/tool_call_repair.py` handles malformed LLM-generated tool calls:

### Repair Strategies

| Issue | Strategy |
|-------|----------|
| Missing required parameters | Inject defaults from tool schema |
| Wrong parameter types | Type coercion (str→int, list→str) |
| Unknown tool names | Levenshtein closest match to known tools |
| Extra unknown parameters | Strip unrecognized fields |
| Invalid enum values | Closest valid match |
| Nested structure errors | Schema-based reconstruction |
| Naming variations | Normalize to canonical parameter names (e.g., `target`=canonical for host/ip/domain/url) |

### Integration

ToolCallRepair intercepts between the LLM output parser and the execution engine, ensuring that only syntactically valid tool calls reach the executor.

---

## Layer 7: Execution Sandboxing

### Tool-Level Sandboxing

Each tool execution is sandboxed through:

| Mechanism | Implementation |
|-----------|----------------|
| **Command isolation** | Tools invoked in subprocess with controlled environment |
| **Timeout enforcement** | Configurable per tool and per step |
| **Resource limits** | Memory limits, output size limits |
| **Working directory** | Sandboxed temp directory per execution |
| **Network restrictions** | Scope-based network access control |

### Scope Enforcement

The PermissionGate and TargetScope work together to enforce operational boundaries:

- Target must match approved scope patterns
- Out-of-scope targets are blocked
- Scope widening requires explicit user approval

---

## Layer 8: Audit & Credential Management

### Tamper-Evident Audit Log

The `AuditLogger` in `siyarix/audit.py` maintains a tamper-evident chain:

```python
# Chain entry
entry = {
    "timestamp": "...",
    "session_id": "...",
    "user": "...",
    "action": "...",
    "target": "...",
    "status": "completed",
    "hash": "sha256_of_previous_entry_hash + content",
    "previous_hash": "...",
}
```

Each entry's hash includes the previous entry's hash, creating an immutable chain. Tampering with any entry breaks all subsequent hashes.

### CredentialStore

The `CredentialStore` in `siyarix/credential_store.py` manages credentials:

| Feature | Implementation |
|---------|----------------|
| **Storage** | Encrypted JSON file with Fernet symmetric encryption |
| **Key management** | Derived from user-provided master password via PBKDF2 |
| **Provider credentials** | Stored per provider profile, loaded on demand |
| **Scope** | Used for target authentication, not for API keys |

### Provider Credentials

Provider API keys are loaded from (in priority order):

1. Environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.)
2. Encrypted credential store
3. Configuration file (not recommended for production)

---

## Security Commands

Siyarix exposes a security command group in `siyarix/security_commands.py`:

```bash
siyarix security audit-log          # View audit trail
siyarix security verify-chain       # Verify audit chain integrity
siyarix security credential-store   # Manage credential store
siyarix security permissions        # Manage permission policies
siyarix security scope              # Manage operational scope
siyarix security session-list       # List active sessions
```

---

## Threat Model

| Threat | Mitigation Layer | Severity |
|--------|-----------------|----------|
| Prompt injection via user input | Validators (shell injection, length) | High |
| AI suggests destructive command | Permission Gate (38+ danger sigs) | High |
| Sensitive data sent to AI API | DLP Engine (24+ data patterns) | Critical |
| Operator OPSEC exposure | OPSEC Manager (proxy, DoH, jitter) | Medium |
| Detection by defensive systems | Stealth Engine (tiers, evasion) | Medium |
| Malformed LLM tool calls | ToolCallRepair (schema repair) | Medium |
| Audit log tampering | SHA-256 chain | Critical |
| Credential exfiltration | Encrypted store, no plaintext | High |
| Tool misuse / hallucination | Validator + ToolRegistry validation | Medium |
| Unauthorized scope access | Permission Gate + TargetScope | High |

---

## Safety Policy References

Safety levels are set via the `SIYARIX_SAFE_MODE` environment variable:

| Value | Permission Gate | DLP | OPSEC | Stealth |
|-------|----------------|-----|-------|---------|
| `strict` (default) | ALLOW/REVIEW/BLOCK | REDACT | MEDIUM | 1 |
| `permissive` | ALLOW/REVIEW | WARN | OFF | 0 |
