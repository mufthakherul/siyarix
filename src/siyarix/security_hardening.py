# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Security Hardening — Input Validation, Secret Redaction, Danger Analysis.

Provides three production-grade security primitives:

  • **InputValidator** — sanitises IP/hostname/URL targets, detects injection
    patterns including shell metacharacters, path traversal, and SQL keywords.
  • **SecretRedactor** — strips API keys, passwords, tokens, JWTs, and cloud
    provider credentials from logs and command output before display.
  • **DangerAnalyzer** — classifies commands by destructiveness (critical /
    high / medium / low / info / safe) before execution, supporting both
    Linux and Windows-specific destructive patterns.

Module-level singletons are exported for easy import::

    from siyarix.security_hardening import validator, redactor, danger_analyzer

All three classes are stateless and thread-safe.
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

# L-10: Graceful fallback when rich is not installed.
try:
    from rich.console import Console
    from rich.panel import Panel

    _HAS_RICH = True
except ImportError:  # pragma: no cover
    _HAS_RICH = False
    Console = None  # type: ignore[assignment,misc]
    Panel = None  # type: ignore[assignment,misc]

__all__ = [
    "InputValidator",
    "SecretRedactor",
    "DangerAnalyzer",
    "DangerReport",
    "validator",
    "redactor",
    "danger_analyzer",
]

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# InputValidator
# ═══════════════════════════════════════════════════════════════════════════

# Characters that MUST NOT appear in a target string (shell metacharacters)
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("shell_pipe", re.compile(r"[|;\&`]")),
    ("command_substitution", re.compile(r"\$\(")),
    ("path_traversal", re.compile(r"\.\./|\.\.\\")),
    ("path_traversal_backslash", re.compile(r"\.\.[\\/]")),
    ("path_traversal_encoded", re.compile(r"%2e%2e[/%]", re.IGNORECASE)),
    ("null_byte", re.compile(r"\x00")),
    ("newline_injection", re.compile(r"[\r\n]")),
    ("format_string", re.compile(r"%[0-9]*[nsxp]", re.IGNORECASE)),
    (
        "sql_keyword",
        re.compile(
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|EXEC)\b.*[;'\"]",
            re.IGNORECASE,
        ),
    ),
    ("redirect", re.compile(r"(?:^|(?<=\s))[><]{1,2}(?!\s*/?[a-zA-Z])")),
    ("backtick_exec", re.compile(r"`[^`]+`")),
]

_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")
_URL_RE = re.compile(
    r"^https?://[^\s/\$\.\?#]+\.[^\s]+$",
    re.IGNORECASE,
)


class InputValidator:
    """Validate and sanitise user-supplied targets before they reach the executor.

    Supports IPv4/IPv6 addresses, CIDR blocks, DNS hostnames, and HTTP(S)
    URLs.  All methods are stateless and safe to call from any thread.
    """

    def validate_ip(self, value: str) -> tuple[bool, str]:
        """Validate an IPv4/IPv6 address or CIDR block.

        Returns:
            A ``(valid, error_message)`` tuple.  *error_message* is empty
            when *valid* is ``True``.
        """
        value = value.strip()
        try:
            ipaddress.ip_network(value, strict=False)
            return True, ""
        except ValueError:
            pass
        try:
            ipaddress.ip_address(value)
            return True, ""
        except ValueError:
            return False, f"Invalid IP/CIDR: {value!r}"

    def validate_hostname(self, value: str) -> tuple[bool, str]:
        """Validate a DNS hostname per RFC-952 / RFC-1123.

        Returns:
            A ``(valid, error_message)`` tuple.
        """
        value = value.strip()
        if not value or len(value) > 253:
            return False, "Hostname empty or exceeds 253 characters"
        from .validators import validate_hostname as _validate_hostname

        try:
            _validate_hostname(value)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def validate_url(self, value: str) -> tuple[bool, str]:
        """Validate an HTTP or HTTPS URL.

        Returns:
            A ``(valid, error_message)`` tuple.
        """
        from .validators import validate_url as _validate_url

        value = value.strip()
        try:
            _validate_url(value)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def validate_target(self, value: str) -> tuple[bool, str]:
        """Auto-detect and validate a target (IP, hostname, or URL).

        Runs injection checks **before** format validation so that
        hostile inputs are rejected early.

        Returns:
            A ``(valid, error_message)`` tuple.
        """
        from .validators import validate_target as _validate_target

        value = value.strip()
        if not value:
            return False, "Empty target"
        if len(value) > 4096:
            return False, "Target exceeds maximum length (4096 characters)"

        # Check for injection first
        has_inj, pattern = self.has_injection(value)
        if has_inj:
            return False, f"Injection detected ({pattern}): {value!r}"

        # Delegate to validators.py for target type detection
        try:
            _validate_target(value)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def sanitize_arg(self, value: str) -> str:
        """Strip dangerous characters from a single argument.

        Removes null bytes, backticks, ``$()``, shell operators,
        carriage-returns, newlines, and ANSI escape sequences
        (H-26).  Also collapses ``../`` traversals.

        Returns:
            The sanitised string, stripped of leading/trailing whitespace.
        """
        import urllib.parse
        value = urllib.parse.unquote(value)
        # Remove null bytes, carriage-returns, newlines, ANSI escapes (H-26)
        sanitized = value.replace("\x00", "")
        sanitized = sanitized.replace("\r", "")
        sanitized = sanitized.replace("\n", "")
        sanitized = sanitized.replace("\x1b", "")
        # Remove shell metacharacters but allow $ for valid env vars/regexes
        sanitized = re.sub(r"[`|;&><]", "", sanitized)
        # Remove command substitution
        sanitized = re.sub(r"\$\(|\$\{", "", sanitized)
        while "../" in sanitized or "..\\" in sanitized:
            sanitized = sanitized.replace("../", "").replace("..\\", "")
        return sanitized.strip()

    def sanitize_args(self, args: list[str]) -> list[str]:
        """Sanitise every argument in *args* individually.

        Returns:
            A new list with each element sanitised via :meth:`sanitize_arg`.
        """
        return [self.sanitize_arg(a) for a in args]

    def has_injection(self, value: str) -> tuple[bool, str]:
        """Check a single string for injection patterns.

        Returns:
            A ``(detected, pattern_name)`` tuple.  *pattern_name* is the
            human-readable label of the first matching pattern, or ``""``
            when nothing suspicious is found.
        """
        for name, pattern in _INJECTION_PATTERNS:
            if pattern.search(value):
                return True, name
        return False, ""

    def check_args_injection(self, args: list[str]) -> tuple[bool, str]:
        """Check a list of arguments for injection patterns.

        Each argument is inspected **individually** so that joining them
        with whitespace cannot create false cross-arg patterns (M-07).

        Returns:
            A ``(detected, pattern_name)`` tuple for the first offending
            argument, or ``(False, "")`` if all arguments are clean.
        """
        for arg in args:
            found, name = self.has_injection(arg)
            if found:
                return True, name
        return False, ""


# ═══════════════════════════════════════════════════════════════════════════
# SecretRedactor
# ═══════════════════════════════════════════════════════════════════════════

_REDACT_PLACEHOLDER = "[REDACTED]"

_REDACT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # ── API keys ──────────────────────────────────────────────────────────
    ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # H-10: preserve the key name, only redact the value after = or :.
    (
        "aws_secret_key",
        re.compile(
            r"(?i)(aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*)\S+",
        ),
    ),
    # Anthropic API keys (sk-ant-…)
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    # DeepSeek API keys
    ("deepseek_key", re.compile(r"sk-ds[A-Za-z0-9_-]{20,}")),
    # xAI (Grok) API keys
    ("xai_key", re.compile(r"xai-[A-Za-z0-9_-]{20,}")),
    # Mistral API keys
    ("mistral_key", re.compile(r"(?i)mistral[_-]?api[_-]?key\s*[=:]\s*\S+")),
    ("bearer_token", re.compile(r"(?i)Bearer\s+[A-Za-z0-9_.~+/=-]{20,}")),
    ("basic_auth", re.compile(r"(?i)Basic\s+[A-Za-z0-9+/=]{10,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    (
        "generic_api_key",
        re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_.~+/=-]{16,}['\"]?"),
    ),
    # ── Cloud provider credentials ───────────────────────────────────────
    # Google Cloud service account key file markers
    (
        "gcp_service_account",
        re.compile(r'"type"\s*:\s*"service_account"'),
    ),
    # Azure connection strings
    (
        "azure_connection_string",
        re.compile(
            r"(?i)(?:DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)"
            r"=[A-Za-z0-9+/=]+",
        ),
    ),
    # ── Passwords in URLs ────────────────────────────────────────────────
    ("url_password", re.compile(r"://[^:]+:([^@]{3,})@")),
    # ── Private key markers ──────────────────────────────────────────────
    ("private_key", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
    # ── Generic secret-like key=value ────────────────────────────────────
    (
        "secret_kv",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|token|auth|credential|private[_-]?key)\s*[=:]\s*\S+",
        ),
    ),
    # ── JWT tokens ───────────────────────────────────────────────────────
    (
        "jwt_token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
        ),
    ),
    # ── Slack tokens ─────────────────────────────────────────────────────
    ("slack_token", re.compile(r"xox[bporas]-[0-9A-Za-z-]+")),
    # ── Gemini / Google API keys ─────────────────────────────────────────
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
]

_SENSITIVE_KEY_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "auth",
        "credential",
        "private_key",
        "access_key",
        "secret_key",
        "bearer",
        "authorization",
    }
)


class SecretRedactor:
    """Detect and replace secrets, credentials, and tokens in text and dicts.

    Covers OpenAI, Anthropic, DeepSeek, xAI, Mistral, AWS, GCP, Azure,
    GitHub, Slack, Google, JWTs, private keys, Bearer/Basic auth, and
    generic ``key=value`` patterns.  All methods are stateless.
    """

    def redact(self, text: str) -> str:
        """Return *text* with all detected secrets replaced by ``[REDACTED]``.

        For patterns that capture a key-name group (e.g. ``aws_secret_key``),
        only the **value** portion is redacted while the key name is preserved
        (H-10).
        """
        result = text
        for _name, pattern in _REDACT_PATTERNS:
            if pattern.groups >= 1:
                # Preserve the captured key-name prefix, redact the rest.
                result = pattern.sub(rf"\g<1>{_REDACT_PLACEHOLDER}", result)
            else:
                result = pattern.sub(_REDACT_PLACEHOLDER, result)
        return result

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Deep-copy *data* and redact all string values that look secret.

        Keys whose names match :data:`_SENSITIVE_KEY_WORDS` are
        unconditionally redacted; all other string values are passed
        through :meth:`redact` for pattern-based detection.
        """
        out = copy.deepcopy(data)
        self._walk_dict(out)
        return out

    def is_sensitive_key(self, key: str) -> bool:
        """Return ``True`` if *key* looks like it stores a secret.

        Matching is case-insensitive and treats hyphens as underscores.
        """
        lower = key.lower().replace("-", "_")
        return any(w in lower for w in _SENSITIVE_KEY_WORDS)

    # -- internal -------------------------------------------------------

    def _walk_dict(self, obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    if self.is_sensitive_key(k):
                        obj[k] = _REDACT_PLACEHOLDER
                    else:
                        obj[k] = self.redact(v)
                elif isinstance(v, (dict, list)):
                    self._walk_dict(v)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = self.redact(item)
                elif isinstance(item, (dict, list)):
                    self._walk_dict(item)

    def redact_env(self) -> dict[str, str]:
        """Return a copy of the current environment with sensitive values redacted.

        Iterates over :data:`os.environ` and replaces values whose keys
        match :meth:`is_sensitive_key` with ``[REDACTED]``.  Non-sensitive
        values are passed through :meth:`redact` for pattern-based checks.

        Returns:
            A new ``dict[str, str]`` — the real environment is never mutated.
        """
        out: dict[str, str] = {}
        for key, value in os.environ.items():
            if self.is_sensitive_key(key):
                out[key] = _REDACT_PLACEHOLDER
            else:
                out[key] = self.redact(value)
        return out


# ═══════════════════════════════════════════════════════════════════════════
# DangerAnalyzer
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class DangerReport:
    """Assessment of how dangerous a command is.

    Attributes:
        is_dangerous: ``True`` when at least one pattern matched.
        severity: The highest severity among all matches — one of
            ``'critical'``, ``'high'``, ``'medium'``, ``'low'``,
            ``'info'``, or ``'safe'``.
        reasons: Human-readable descriptions of every matched pattern.
        recommendation: Suggested action (block / confirm / caution / info).
        matched_patterns: Raw regex patterns that fired.
    """

    is_dangerous: bool
    severity: str  # 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe'
    reasons: list[str] = field(default_factory=list)
    recommendation: str = ""
    matched_patterns: list[str] = field(default_factory=list)

    @property
    def requires_confirmation(self) -> bool:
        """Return ``True`` when the user should confirm before execution."""
        return self.severity in ("critical", "high", "medium")


_DANGER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # (pattern, severity, description)
    # ── CRITICAL ──
    (
        re.compile(r"\bsudo\s+rm\s+-[a-zA-Z]*r", re.I),
        "critical",
        "sudo rm -r",
    ),
    (
        re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*[rf]", re.I),
        "critical",
        "Recursive force delete (rm -rf)",
    ),
    (
        re.compile(r"\bmkfs\b", re.I),
        "critical",
        "Format disk (mkfs)",
    ),
    (
        re.compile(r"\bdd\s+if=", re.I),
        "critical",
        "Raw disk overwrite (dd)",
    ),
    (
        re.compile(r">\s*/dev/sd[a-z]", re.I),
        "critical",
        "Write to block device",
    ),
    (
        re.compile(r"\bmv\s+/.*\s+/dev/null", re.I),
        "critical",
        "Move files to /dev/null (data destruction)",
    ),
    (
        re.compile(r">\s*/etc/(?:passwd|shadow|sudoers)", re.I),
        "critical",
        "Overwrite auth files",
    ),
    (
        re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;", re.I),
        "critical",
        "Bash fork bomb",
    ),
    (
        # H-09: start-of-line or word-boundary + the command name + args
        # ensures "chmod" inside tool names like "wichmod" won't match.
        re.compile(r"(?:^|(?<=\s))chmod\s+777\s+/", re.I | re.M),
        "critical",
        "World-writable root (chmod 777 /)",
    ),
    # ── HIGH ──
    (re.compile(r"\bshutdown\b", re.I), "high", "System shutdown"),
    (re.compile(r"\breboot\b", re.I), "high", "System reboot"),
    (re.compile(r"\bhalt\b", re.I), "high", "System halt"),
    (re.compile(r"\binit\s+0\b", re.I), "high", "init 0 (shutdown)"),
    (
        re.compile(r"\bchown\s+.*\s+/(?!tmp)", re.I),
        "high",
        "chown on system directories",
    ),
    (re.compile(r">\s*/etc/", re.I), "high", "Overwrite system config"),
    (
        re.compile(r"\bcurl\b.*\|\s*(?:sudo\s+)?(?:bash|sh|python)\b", re.I),
        "high",
        "Pipe curl to shell/python",
    ),
    (
        re.compile(r"\bwget\b.*\|\s*(?:sudo\s+)?(?:bash|sh|python)\b", re.I),
        "high",
        "Pipe wget to shell/python",
    ),
    (re.compile(r"\bDROP\s+(?:TABLE|DATABASE)\b", re.I), "high", "SQL DROP statement"),
    (
        re.compile(r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", re.I),
        "high",
        "SQL DELETE without WHERE",
    ),
    (re.compile(r"\bTRUNCATE\s+TABLE\b", re.I), "high", "SQL TRUNCATE TABLE"),
    # ── MEDIUM ──
    (re.compile(r"\brm\s+", re.I), "medium", "File deletion (rm)"),
    (re.compile(r"\bkillall\b", re.I), "medium", "Kill all processes"),
    (re.compile(r"\bpkill\s+-9\b", re.I), "medium", "Force kill processes"),
    (re.compile(r"\biptables\s+-F\b", re.I), "medium", "Flush firewall rules"),
    (re.compile(r"\bufw\s+disable\b", re.I), "medium", "Disable firewall"),
    (
        re.compile(r"\bsystemctl\s+(?:stop|disable)\b", re.I),
        "medium",
        "Stop/disable service",
    ),
    (
        re.compile(r"\bnc\s+-[a-zA-Z]*l", re.I),
        "medium",
        "Netcat listener (possible reverse shell)",
    ),
    (
        re.compile(r"\bpython[23]?\s+-c\s+.*socket", re.I),
        "medium",
        "Python socket (possible reverse shell)",
    ),
    (re.compile(r"/dev/tcp/", re.I), "medium", "Bash /dev/tcp (reverse shell pattern)"),
    (re.compile(r"\bxmrig\b", re.I), "medium", "Cryptominer (xmrig)"),
    (re.compile(r"\bcpuminer\b", re.I), "medium", "Cryptominer (cpuminer)"),
    (re.compile(r"\bcrontab\s+-e\b", re.I), "medium", "Edit crontab (persistence)"),
    (re.compile(r">>\s*(?:~/\.bashrc|~/\.zshrc|~/\.profile)", re.I), "medium", "Modify shell rc (persistence)"),
    (re.compile(r"\bbase64\s+-d\s*\|", re.I), "high", "Base64 decode pipe (encoded execution)"),
    (re.compile(r"\|\s*base64\s+-d\b", re.I), "high", "Pipe to base64 decode (encoded execution)"),
    (re.compile(r"\bcat\s+(?:/etc/shadow|~/\.ssh/|/root/\.ssh/)", re.I), "critical", "Credential exfiltration (shadow/ssh)"),
    # ── Windows-specific ──
    (re.compile(r"\bformat\s+[a-zA-Z]:", re.I), "critical", "Windows format disk"),
    (
        re.compile(r"\bdel\s+/[fF]\s+[a-zA-Z]:\\", re.I),
        "critical",
        "Windows force delete system drive",
    ),
    (re.compile(r"\breg\s+delete\s+HKLM", re.I), "critical", "Windows registry delete (HKLM)"),
    (
        re.compile(r"\bbcdedit\s+/set\s+{default}\s+.*\b(?:boot|recovery)sequence", re.I),
        "critical",
        "Windows boot config tampering",
    ),
    (re.compile(r"\bdiskpart\b", re.I), "high", "Windows disk partition manipulation"),
    (
        re.compile(r"\bvssadmin\s+delete\s+shadows", re.I),
        "high",
        "Windows volume shadow copy deletion",
    ),
    (
        re.compile(r"\bwmic\s+(?:shadowcopy|volume)\s+delete", re.I),
        "high",
        "Windows WMIC volume deletion",
    ),
    (re.compile(r"\bwevtutil\s+cl\b", re.I), "high", "Windows event log clearing"),
    (re.compile(r"\bcipher\s+/w:", re.I), "medium", "Windows disk overwrite (cipher /w)"),
    (
        re.compile(r"\bnet\s+(?:user|localgroup)\s+/delete", re.I),
        "medium",
        "Windows user/group deletion",
    ),
    (
        re.compile(r"\bpowershell\s+.*-EncodedCommand\b", re.I),
        "medium",
        "PowerShell encoded command (obfuscation)",
    ),
    (re.compile(r"\bsc\s+(?:stop|delete)\s+\w+", re.I), "medium", "Windows service stop/delete"),
    (
        re.compile(r"\breg\s+add\s+HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", re.I),
        "medium",
        "Windows registry persistence (Run key)",
    ),
    (re.compile(r"\bschtasks\s+/create\b", re.I), "medium", "Windows scheduled task creation"),
    (
        re.compile(r"\bGet-WmiObject\s+Win32_ShadowCopy\b.*\bDelete\(\)", re.I),
        "medium",
        "PowerShell WMI shadow copy deletion",
    ),
    # ── LOW ──
    # H-09: use start-of-line-aware pattern so tool names containing
    # "chmod" (e.g. "gochmod") don't false-positive.
    (re.compile(r"(?:^|(?<=\s))chmod\b", re.I | re.M), "low", "Permission change (chmod)"),
    (re.compile(r"\bchown\b", re.I), "low", "Ownership change (chown)"),
    (re.compile(r"\bcrontab\b", re.I), "low", "Crontab modification"),
]

_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "safe": 0,
}


class DangerAnalyzer:
    """Classify commands by destructiveness before execution.

    Matches against a comprehensive list of Linux and Windows patterns
    covering file deletion, disk formatting, registry manipulation,
    reverse shells, cryptominers, and privilege escalation.
    """

    def analyze(self, command: str) -> DangerReport:
        """Analyse *command* against all known danger patterns.

        Returns:
            A :class:`DangerReport` whose *severity* is the highest
            severity among all matching patterns.
        """
        if not command or not command.strip():
            return DangerReport(is_dangerous=False, severity="safe")

        reasons: list[str] = []
        matched: list[str] = []
        max_severity = "safe"

        for pattern, severity, description in _DANGER_PATTERNS:
            if pattern.search(command):
                reasons.append(f"[{severity.upper()}] {description}")
                matched.append(pattern.pattern)
                if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(max_severity, 0):
                    max_severity = severity

        is_dangerous = max_severity != "safe"
        recommendation = ""
        if max_severity == "critical":
            recommendation = "⛔ BLOCK — This command is destructive and should NOT be executed."
        elif max_severity == "high":
            recommendation = (
                "⚠️  CONFIRM — This command is high-risk. Require explicit user confirmation."
            )
        elif max_severity == "medium":
            recommendation = "⚡ CAUTION — Review this command before execution."
        elif max_severity == "low":
            recommendation = "ℹ️  INFO — Low-risk operation; proceed with awareness."
        elif max_severity == "info":
            recommendation = "📝 NOTE — Informational; no action required."

        return DangerReport(
            is_dangerous=is_dangerous,
            severity=max_severity,
            reasons=reasons,
            recommendation=recommendation,
            matched_patterns=matched,
        )

    def format_warning(self, report: DangerReport, console: Any | None = None) -> None:
        """Print a formatted danger warning to a Rich console.

        When *rich* is not installed the method silently returns so that
        callers do not need to guard imports (L-10).
        """
        if not report.is_dangerous:
            return
        if not _HAS_RICH:
            logger.warning(
                "DangerAnalyzer.format_warning: rich is not installed; "
                "cannot render panel.  Severity=%s",
                report.severity,
            )
            return
        c = console or Console()
        color_map = {
            "critical": "bold bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }
        style = color_map.get(report.severity, "white")
        icon_map = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
        }
        icon = icon_map.get(report.severity, "⚪")

        lines = [f"[{style}]{icon} DANGER LEVEL: {report.severity.upper()}[/{style}]"]
        for reason in report.reasons:
            lines.append(f"  • {reason}")
        lines.append(f"\n[bold]{report.recommendation}[/bold]")

        c.print(
            Panel(
                "\n".join(lines),
                title=f"[{style}]⚠ Security Alert[/{style}]",
                border_style=style,
            )
        )

    def get_danger_summary(self, command: str) -> str:
        """Return a one-line human-readable danger summary for *command*.

        Convenience wrapper around :meth:`analyze` that returns a compact
        string suitable for log messages or CLI output.

        Returns:
            A string like ``"CRITICAL: sudo rm -r, Recursive force delete"``
            or ``"safe"`` when no patterns matched.
        """
        report = self.analyze(command)
        if not report.is_dangerous:
            return "safe"
        reason_texts = ", ".join(
            r.split("] ", 1)[1] if "] " in r else r for r in report.reasons
        )
        return f"{report.severity.upper()}: {reason_texts}"


# ═══════════════════════════════════════════════════════════════════════════
# Module-level singletons
# ═══════════════════════════════════════════════════════════════════════════

validator = InputValidator()
redactor = SecretRedactor()
danger_analyzer = DangerAnalyzer()
