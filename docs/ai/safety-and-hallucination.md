# 🛡️ Safety, Security & Hallucination Resistance

!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Welcome to the core of Siyarix's defense mechanism! When operating an autonomous or semi-autonomous AI system, safety and security are paramount.

!!! info
    Siyarix implements a robust, multi-layered safety architecture designed to protect your host system, secure operator data, and maintain the absolute integrity of your audit trails. Every single command passes through stages of validation, danger classification, secret redaction, and interactive review before it ever executes.

---

## 🛤️ The Safety Pipeline

Think of the safety pipeline as a series of rigorous checkpoints. Every tool and command must successfully pass through these stages before execution:

!!! note
    **Workflow:** `User input` ➔ `InputValidator` ➔ `PermissionGate` ➔ `DangerAnalyzer` ➔ `DLPEngine` ➔ `ShellReview` ➔ `AuditLogger`

---

## 1. 🔍 InputValidator

Located in `src/siyarix/security_hardening.py`, the **InputValidator** is your first line of defense. It thoroughly validates and sanitizes any user-supplied targets to ensure they are safe before reaching the executor.

### 🎯 Target Validation

The validator automatically detects and verifies the format of your targets:

```python
from siyarix.security_hardening import validator

# Validates IP, hostname, or URL seamlessly
valid, msg = validator.validate_target("10.0.0.1")
valid, msg = validator.validate_ip("192.168.1.0/24")
valid, msg = validator.validate_hostname("example.com")
valid, msg = validator.validate_url("https://example.com")
```

### 💉 Injection Detection

To prevent malicious activity, the validator actively looks for and blocks shell injection patterns:

!!! warning
    Any command containing the following patterns will be immediately blocked to prevent shell injection attacks.

| Pattern | Example | Severity |
|---------|---------|----------|
| Shell pipe/redirection | `|`, `;`, `&`, `` ` `` | ⛔ Blocked |
| Command substitution | `$(...)` | ⛔ Blocked |
| Path traversal | `../`, `..\\`, `%2e%2e` | ⛔ Blocked |
| Null byte | `\x00` | ⛔ Blocked |
| Newline injection | `\r\n` | ⛔ Blocked |
| Format string | `%x`, `%n` | ⛔ Blocked |
| SQL injection keywords | `SELECT`, `DROP`, `UNION` + `'` or `"` | ⛔ Blocked |
| Backtick execution | `` `cmd` `` | ⛔ Blocked |

### 🧼 Argument Sanitisation

If you need to clean up an argument safely, the validator can strip out dangerous characters:

```python
safe = validator.sanitize_arg("target; rm -rf /")
# Returns: "target rm -rf " (shell metacharacters stripped)
```

!!! tip
    This sanitisation removes null bytes, carriage returns, newlines, ANSI escape sequences, backticks, `$()`, `${}`, `|`, `;`, `&`, `<`, `>`, and collapses dangerous `../` path traversals.

---

## 2. ⚠️ DangerAnalyzer

Also found in `src/siyarix/security_hardening.py`, the **DangerAnalyzer** evaluates commands to determine how destructive they might be before they are allowed to run.

### 🚥 Danger Levels

Commands are classified into six severity levels, guiding how the system responds:

| Severity | Recommendation | Example Patterns |
|----------|---------------|------------------|
| **Critical** | ⛔ Blocked | `sudo rm -rf /`, `mkfs`, `dd if=`, fork bombs, format drive, `chmod 777 /`, credential exfiltration |
| **High** | ✋ Confirm | `shutdown`, `reboot`, `halt`, pipe curl/wget to shell, SQL DROP/DELETE without WHERE, `Remove-Item -Recurse` |
| **Medium** | ⚡ Caution | `rm`, `killall`, `iptables -F`, netcat listener, crontab edit, PowerShell encoded command |
| **Low** | ℹ️ Info | `chmod`, `chown`, `crontab` |
| **Info** | 📝 Note | `sudo` |
| **Safe** | ✅ — | No patterns matched |

### 🛠️ Usage

Using the analyzer is straightforward:

```python
from siyarix.security_hardening import danger_analyzer

report = danger_analyzer.analyze("rm -rf /tmp")
print(report.severity)        # "medium"
print(report.is_dangerous)    # True
print(report.recommendation)  # "⚡ CAUTION — Review this command before execution."
```

!!! note
    The analyzer protects both Linux and Windows environments, covering destructive patterns like registry manipulation, shadow copy deletion, event log clearing, and scheduled task abuse.

### 🎨 Formatted Warning

You can also output these warnings directly to the console with beautiful, color-coded formatting:

```python
from rich.console import Console
danger_analyzer.format_warning(report, Console())
```

---

## 3. 🚧 PermissionGate

Located in `src/siyarix/permission_gate.py`, the **PermissionGate** acts as the bouncer for your runtime environment, providing a strict two-stage safety enforcement protocol.

### ⚖️ Two-Stage Check

1. **Stage 1 — Syntax Check**: Ensures the command is not empty and is syntactically valid.
2. **Stage 2 — Danger Analysis**: Consults the `DangerAnalyzer` and decides what action to take based on the severity:

| Danger Severity | Gate Result | Action |
|----------------|-------------|--------|
| `critical` | `FORBIDDEN` | Blocked with a clear reason. |
| `high` / `medium` | `REVIEW` | Allowed, but flagged with `requires_review=True`. |
| `low` / `info` / `safe` | `APPROVED` | Approved for execution. |

### ⏱️ Rate Limiting

To prevent abuse or runaway scripts, the gate limits how often commands can be called:

```python
gate = PermissionGate(rate_limit_calls=100, rate_limit_period=60.0)
```

!!! tip
    By default, the limit is 100 calls per 60 seconds. The state is saved in `rate_limit.json` in your config directory. Exceeding this limit results in a `FORBIDDEN` action.

### 🧨 Restricted Payload Detection

If you pass `context={"restricted_payload": True}`, the gate proactively checks for highly destructive patterns (like `rm -rf`, `mkfs`, `dd if=`) *before* even applying the rate limit.

### 📊 Gate Stages Overview

The gate returns a `GateResult` dataclass indicating the command's status:

| Stage | What it Means |
|-------|---------|
| `SYNTAX` | Failed basic syntax validation. |
| `FORBIDDEN` | Blocked either by danger analysis or rate limiting. |
| `PERMISSION` | Currently under permission evaluation. |
| `REVIEW` | Passed syntax checks, but requires manual user review. |
| `APPROVED` | Fully approved and ready for execution. |

---

## 4. 🕵️‍♂️ DLPEngine (Data Loss Prevention)

Found in `src/siyarix/dlp.py`, the **DLPEngine** scans tool outputs and automatically redacts sensitive information to prevent leaks.

### 🔐 Redaction Patterns

| Category | Patterns Handled |
|----------|----------|
| **Secrets** | AWS keys (`AKIA...`), GCP keys (`AIza...`), Slack tokens (`xoxb-...`), GitHub tokens (`ghp_...`), Bearer tokens, Private keys (PEM) |
| **PII** (Optional) | Email addresses, US Social Security numbers |

### 🛠️ Usage

```python
from siyarix.dlp import DLPEngine

dlp = DLPEngine(redact_secrets=True, redact_pii=False)

safe_output = dlp.redact("API key: AKIAIOSFODNN7EXAMPLE")
# Returns: "API key: [REDACTED AWS_KEY]"

safe_dict = dlp.redact_dict({"token": "ghp_xxxxxxxxxxxxxxxxxxxx"})
```

!!! note
    Secrets aren't just hidden; they are clearly labeled with their category name (e.g., `[REDACTED AWS_KEY]`) so you know exactly what was removed.

### 🛡️ SecretRedactor (Comprehensive)

For even stricter redaction, `security_hardening.py` provides a `SecretRedactor` that covers over 20+ patterns, including AI API keys (OpenAI, Anthropic, DeepSeek, xAI, Mistral), cloud credentials, and generic `password=value` pairs.

```python
from siyarix.security_hardening import redactor

safe = redactor.redact("Key: sk-ant-xxxxxxxxxxxxxxxxxxxx")
safe_env = redactor.redact_env()  # Automatically masks secrets in os.environ
```

---

## 5. 🧑‍💻 ShellReview

Located in `src/siyarix/shell_review.py`, the **ShellReview** module pauses execution to let the human operator review what the AI wants to run.

### 👁️ Review Prompt

When a command needs review, the operator sees a clean, interactive prompt:

```text
╭──────────────── Command Execution Review ─────────────────╮
│ Tool: raw                                                 │
│ Reason: Raw shell command from LLM plan                   │
│                                                           │
│ nmap -sS -sV -O -Pn example.com                           │
╰───────────────────────────────────────────────────────────╯
Review command [edit/run/step/cancel] (run):
```

### 🕹️ Review Decisions

The operator has four choices:

| Decision | Behavior |
|----------|----------|
| `run` | Execute the command exactly as shown. |
| `edit` | Interactively modify the command before running it. |
| `step` | Execute, but step through subsequent commands one by one. |
| `cancel` | Skip or cancel this command entirely. |

!!! tip
    **CI / Non-TTY Mode:** If the system detects it's running in a non-interactive environment (like a CI pipeline), it will automatically approve commands to prevent the process from hanging indefinitely.

---

## 6. 📜 AuditLogger

Located in `src/siyarix/audit_log.py`, the **AuditLogger** provides an solid audit trail with a tamper-evident chain of custody, ensuring absolute accountability.

### 🧩 The Event System

Every single action generates a structured `AuditEvent`:

```python
@dataclass
class AuditEvent:
    event_id: str               # Unique UUID hex
    timestamp: datetime         # UTC timestamp
    event_type: str             # Category of the event
    severity: str               # info / low / medium / high / critical
    user: str                   # The user who triggered the event
    session_id: str             # Unique session identifier
    source_ip: str              # Originating IP address
    target: str                 # What resource was targeted
    action: str                 # The action performed
    result: str                 # success / failure / denied
    details: dict               # Any extra structured data
    hash_prev: str | None       # Link to the previous event's hash
    hash_current: str | None    # This event's hash
```

### 🔗 Tamper-Evident Chain

To guarantee that logs haven't been altered, each event's hash incorporates the hash of the *previous* event, creating an unbreakable chain.

!!! info
    You can verify the integrity of your entire audit chain at any time. If someone tries to modify a past log entry, the chain will break, and the system will alert you.

```python
audit = AuditLogger()
result = audit.verify_chain() # Returns a validation dictionary
```

### 🏷️ Event Types

There are 87 defined event types spanning across multiple categories, including:
- **Authentication:** `auth_login`, `auth_logout`
- **Security:** `security_approval`, `dlp_violation`, `rate_limit_hit`
- **System:** `system_start`, `config_change`

### 💾 Export & CLI

You can easily export your logs or check status via code or CLI commands:

| Command | Purpose |
|---------|---------|
| `/audit status` | View audit statistics and check chain integrity. |
| `/audit export` | Export logs to JSON or CSV formats. |
| `/audit verify` | Manually verify the tamper-evident chain. |

!!! note
    By default, logs are retained for 365 days. In highly sensitive "OpSec Memory-Only" mode, events are tracked in memory and *never* written to disk.

---

## 7. 🐳 SeccompProfile

Found in `security_hardening.py`, this module generates Docker-compatible `seccomp` profiles to heavily sandbox executions.

### 🚫 Restricted Syscalls

It proactively blocks over 50 dangerous system calls (like `mount`, `ptrace`, `reboot`, and `add_key`) while still allowing standard tools to function normally.

```python
from siyarix.security_hardening import SeccompProfile

profile_path = SeccompProfile.generate_docker_seccomp()
# Returns the path to your secure JSON profile
```

---

## 8. ✅ Validator

Located in `src/siyarix/validators.py`, the **Validator** class focuses on ensuring that inputs and AI-generated plans are formatted correctly and make sense.

### 📐 Validated Types

It handles strict formatting checks for elements like:
- IP Addresses (IPv4/IPv6) & CIDR blocks
- RFC-compliant Hostnames & URLs
- Ports, Port Ranges, and Emails

### 🤖 PlanStep Validation & Recovery

Before the AI executes a plan, the validator checks every `PlanStep` (e.g., verifying it has a tool, arguments, and a valid timeout).

!!! tip
    If a command fails, `plan_recovery()` steps in to suggest smart, automated fixes. For example, if `nmap` reports all filtered ports, the recovery planner might automatically suggest adding the `-Pn` flag to try again.

---

## 📚 Module Quick Reference

Need to dive into the code? Here's where to find everything:

| Module | Location | Purpose |
|--------|------|---------|
| **InputValidator** | `src/siyarix/security_hardening.py:88` | Validates targets and detects shell injection. |
| **DangerAnalyzer** | `src/siyarix/security_hardening.py:650` | Classifies the danger level of commands. |
| **SecretRedactor** | `src/siyarix/security_hardening.py:328` | Masks API keys, tokens, and passwords. |
| **PermissionGate** | `src/siyarix/permission_gate.py:49` | Enforces syntax checks and danger policies. |
| **DLPEngine** | `src/siyarix/dlp.py:29` | Prevents sensitive data loss in outputs. |
| **ShellReview** | `src/siyarix/shell_review.py:48` | Human-in-the-loop interactive reviews. |
| **AuditLogger** | `src/siyarix/audit_log.py:194` | Tamper-evident, personal auditing. |
| **Validator** | `src/siyarix/validators.py:598` | Format validation and AI plan recovery. |
| **SeccompProfile** | `src/siyarix/security_hardening.py:771` | Docker syscall restriction profiles. |

---

*This document serves as your guide to maintaining a secure, hallucination-resistant, and auditable Siyarix environment.*
