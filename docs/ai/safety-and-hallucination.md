# Safety & Hallucination Handling

Siyarix implements multiple production-grade safeguards to prevent AI hallucination, dangerous command generation, output leakage, and injection attacks. The safety architecture spans input validation, danger classification, secret redaction, multi-provider ensemble hallucination detection, and tamper-evident audit logging.

---

## Command Safety (DangerAnalyzer)

`DangerAnalyzer` (in `src/siyarix/security_hardening.py:651`) classifies every command before execution against **40+ danger patterns** covering Linux and Windows destructive operations.

### Danger Severity Levels

| Level | Action | Examples |
|-------|--------|----------|
| `critical` | Blocked — never executed | `sudo rm -rf /`, `mkfs`, `dd if=`, fork bombs, `chmod 777 /` |
| `high` | Requires explicit user confirmation | `shutdown`, `reboot`, `DROP TABLE`, `curl | bash`, credential exfiltration |
| `medium` | Flagged for review | `rm` (file deletion), firewall disable, reverse shell patterns, cryptominers, persistence mechanisms |
| `low` | Informational | `chmod`, `chown`, `crontab` |
| `info` | Noted | `sudo` usage |
| `safe` | Executes immediately | No dangerous patterns matched |

### Danger Pattern Categories

| Category | Patterns |
|----------|----------|
| System destruction | `sudo rm -rf /`, `mkfs`, `dd if=`, `> /dev/sdX`, fork bombs |
| Data destruction | `mv /... /dev/null`, `> /etc/passwd`, `shred`, `wipe` |
| Privilege escalation | `chmod 777 /`, `chown /`, `sudo !!` |
| Credential exfiltration | `cat /etc/shadow`, `cat ~/.ssh/` |
| Remote code execution | `curl | bash`, `wget | sh`, `base64 -d \|` |
| Reverse shells | `nc -l`, `python -c socket`, `/dev/tcp` |
| Persistence | `crontab -e`, `>> ~/.bashrc`, registry Run keys |
| Cryptominers | `xmrig`, `cpuminer` |
| Windows-specific | `format C:`, `diskpart`, `vssadmin delete shadows`, `wevtutil cl`, `Clear-EventLog`, PowerShell encoded commands, `reg delete HKLM`, `bcdedit /set`, `schtasks` |

### Programmatic Usage

```python
from siyarix.security_hardening import danger_analyzer

report = danger_analyzer.analyze("nmap -sV target")
print(report.severity)          # "safe"
print(report.is_dangerous)      # False

report = danger_analyzer.analyze("rm -rf /")
print(report.severity)          # "critical"
print(report.recommendation)    # "⛔ BLOCK — This command is destructive"
print(report.requires_confirmation)  # True
```

---

## Input Validation (InputValidator)

`InputValidator` sanitises all user-supplied targets before they reach the executor.

### Injection Pattern Detection

10 injection categories checked before any execution:

| Pattern | Example | Detection |
|---------|---------|-----------|
| Shell pipe | `\|`, `;`, `&` | Regex match |
| Command substitution | `$()` | Regex match |
| Path traversal | `../`, `..\\` | Regex match |
| Null byte | `\x00` | Byte detection |
| Newline injection | `\r`, `\n` | Byte detection |
| Format string | `%n`, `%s` | Regex match |
| SQL keywords | `SELECT`, `DROP`, `UNION` with quotes | Regex match |
| Redirect | `>`, `>>` | Regex match |
| Backtick execution | `` `cmd` `` | Regex match |

### Target Validation

```python
from siyarix.security_hardening import validator

validator.validate_ip("10.0.0.1")       # (True, "")
validator.validate_ip("999.999.999.999") # (False, "Invalid IP/CIDR")
validator.validate_hostname("example.com")  # (True, "")
validator.validate_url("http://evil.com$(whoami)")  # (False, "Injection detected")

# Auto-detect target type
validator.validate_target("10.0.0.1")    # (True, "")
```

### Argument Sanitization

```python
validator.sanitize_arg("foo; rm -rf /")  # "foo rm -rf "
validator.sanitize_args(["-u", "http://target$(whoami)"])
# Returns: ["-u", "http://target"]
```

---

## Secret Redaction (SecretRedactor)

`SecretRedactor` automatically strips secrets from command output, logs, and environment dumps. Covers 25+ regex patterns across 15 credential types.

### Redacted Credential Types

| Credential | Pattern |
|-----------|---------|
| OpenAI API keys | `sk-[A-Za-z0-9_-]{20,}` |
| Anthropic API keys | `sk-ant-[A-Za-z0-9_-]{20,}` |
| DeepSeek API keys | `sk-ds[A-Za-z0-9_-]{20,}` |
| xAI (Grok) API keys | `xai-[A-Za-z0-9_-]{20,}` |
| AWS access keys | `AKIA[0-9A-Z]{16}` |
| AWS secret keys | Key name preserved, value redacted |
| GitHub tokens | `gh[pousr]_[A-Za-z0-9_]{36,}` |
| Google API keys | `AIza[0-9A-Za-z_-]{35}` |
| JWT tokens | `eyJ...` |
| Bearer tokens | `Bearer [token]` |
| Basic auth | `Basic [base64]` |
| Private keys | `-----BEGIN *PRIVATE KEY-----` |
| Database URLs | `postgres://user:pass@host` |
| Azure connection strings | `AccountKey=...`, `SharedAccessSignature=...` |
| Slack tokens | `xox[bporas]-` |
| Generic secrets | `api_key=...`, `password=...`, `token=...` |

### Usage

```python
from siyarix.security_hardening import redactor

# Text redaction
redactor.redact("API key: sk-proj-abc123def456...")
# Returns: "API key: [REDACTED]"

# Dict redaction (deep copy)
redactor.redact_dict({"config": {"api_key": "sk-secret", "host": "example.com"}})
# Returns: {"config": {"api_key": "[REDACTED]", "host": "example.com"}}

# Environment redaction (safe for logging)
safe_env = redactor.redact_env()  # All sensitive values replaced with [REDACTED]
```

---

## Safe Mode

Activated via environment variable or config:

```bash
export SIYARIX_SAFE_MODE=1
```

In safe mode:

- All destructive commands denied regardless of severity
- Only reconnaissance and scanning permitted
- Permission gate enforces maximum strictness
- Emergency stop via Ctrl+C

---

## Emergency Stop

| Action | Effect |
|--------|--------|
| **Ctrl+C once** | Cancel the current task |
| **Ctrl+C twice** | Exit Siyarix entirely |

The execution engine halts all subprocesses, cleans up, and logs the stop event to the audit trail.

---

## OPSEC Controls

Operational security during assessments (when stealth mode is enabled):

| Control | Description |
|---------|-------------|
| **Decoy requests** | Generate realistic decoy HTTP requests to blend in with normal traffic |
| **User-Agent rotation** | Mimic different browsers |
| **Request jitter** | Random delays between connections |
| **TOR routing** | Anonymize outbound connections (configurable) |
| **DNS over HTTPS** | Prevent DNS-based tracking (configurable) |

```python
# Stealth decoy requests before actual scan
if os.getenv("SIYARIX_STEALTH") == "1":
    engine = StealthEngine()
    reqs = engine.get_decoy_requests(target)
    for req in reqs:
        # Send decoy HTTP requests to blend in
        urllib.request.urlopen(req["url"], timeout=1)
```

---

## Audit Trail

Every safety event is logged to a tamper-evident audit trail:

```json
{
  "timestamp": "2026-06-17T10:30:00Z",
  "event_type": "SAFETY_BLOCK",
  "command": "nmap --script http-slowloris target",
  "reason": "Pattern match: network flooding",
  "severity": "critical",
  "action": "DENY",
  "persona": "blueteam"
}
```

The audit log uses SHA-256 chaining for tamper evidence.

---

## Hallucination Mitigation

### Multi-Provider Ensemble

`ProviderManager.ensemble_decide()` queries multiple providers simultaneously and uses majority voting to detect disagreement:

```python
responses = await asyncio.gather(
    *[pm.complete(p, model, system, user) for p in providers],
    return_exceptions=True,
)
valid = [r["content"] for r in responses if isinstance(r, dict) and "content" in r]
most_common = Counter(valid).most_common(1)[0][0]
```

- **Low variance**: High agreement across providers → low hallucination risk
- **High variance**: Disagreement → potential hallucination, flag for review

### Tool Call Repair

When the LLM outputs malformed tool calls (plain text instead of structured format), `ToolCallRepair` parses and promotes them to native format:

- Bracket syntax: `[tool_name]{"arg": "value"}`
- XML-ish syntax: `<function=name>...</function>`
- Fuzzy name matching with Levenshtein distance ≤ 2 for typo tolerance

```python
from siyarix.tool_call_repair import promote_to_native_tool_calls

cleaned, calls = promote_to_native_tool_calls(
    text="[nmap]{'target': '10.0.0.1', 'flags': '-sV'}",
    allowed_tools=["nmap", "masscan"],
)
```

### Retry with Compaction

When `CONTEXT_OVERFLOW` errors occur, `CompactionEngine` compresses the conversation history and retries:

```python
if classified.should_compress and history:
    compactor = CompactionEngine()
    result = await compactor.compact(history)
    current_history = [{"role": "system", "content": f"Prior context:\n{result.summary}"}]
```

---

## Ethical Constraints

The system enforces ethical boundaries:

- All commands must target systems with explicit authorization
- No denial-of-service commands (flood, stress testing)
- No social engineering tool generation
- All operations must comply with local laws and regulations
- Users must review AI-generated plans before execution (permission gate)

---

## Related Modules

| Module | Path | Purpose |
|--------|------|---------|
| `DangerAnalyzer` | `src/siyarix/security_hardening.py:651` | Command danger classification (40+ patterns) |
| `InputValidator` | `src/siyarix/security_hardening.py:87` | Target validation and injection detection |
| `SecretRedactor` | `src/siyarix/security_hardening.py:329` | Secret/credential redaction (25+ patterns) |
| `danger_analyzer` | `src/siyarix/security_hardening.py:771` | Module-level singleton |
| `ToolCallRepair` | `src/siyarix/tool_call_repair.py` | Parse plain-text tool calls, fuzzy name matching |
| `CompactionEngine` | `src/siyarix/compaction.py` | Context compression for overflow recovery |
| `ProviderManager.ensemble_decide` | `src/siyarix/providers/manager.py:299` | Multi-provider majority voting |
