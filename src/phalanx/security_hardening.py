"""Siyarix Security Hardening — Input Validation, Secret Redaction, Danger Analysis.

Provides three production-grade security primitives:

  • **InputValidator** — sanitises IP/hostname/URL targets, detects injection
  • **SecretRedactor** — strips API keys, passwords, tokens from logs/output
  • **DangerAnalyzer** — classifies commands by destructiveness before execution

Module-level singletons are exported for easy import::

    from siyarix.security_hardening import validator, redactor, danger_analyzer
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel

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
    ("shell_pipe", re.compile(r"[|;&`]")),
    ("command_substitution", re.compile(r"\$\(")),
    ("path_traversal", re.compile(r"\.\./\.\./\.\.")),
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
    ("redirect", re.compile(r"[><]{1,2}")),
    ("backtick_exec", re.compile(r"`[^`]+`")),
]

_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")


class InputValidator:
    """Validates and sanitises user inputs before they reach the executor."""

    def validate_ip(self, value: str) -> tuple[bool, str]:
        """Validate an IPv4/IPv6 address or CIDR block."""
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
        """Validate a DNS hostname."""
        value = value.strip()
        if not value or len(value) > 253:
            return False, "Hostname empty or exceeds 253 characters"
        if _HOSTNAME_RE.match(value):
            return True, ""
        return False, f"Invalid hostname: {value!r}"

    def validate_url(self, value: str) -> tuple[bool, str]:
        """Validate an HTTP/HTTPS URL."""
        value = value.strip()
        if _URL_RE.match(value):
            return True, ""
        return False, f"Invalid URL: {value!r}"

    def validate_target(self, value: str) -> tuple[bool, str]:
        """Auto-detect and validate a target (IP, hostname, or URL)."""
        value = value.strip()
        if not value:
            return False, "Empty target"

        # Check for injection first
        has_inj, pattern = self.has_injection(value)
        if has_inj:
            return False, f"Injection detected ({pattern}): {value!r}"

        # Try IP
        ok, _ = self.validate_ip(value)
        if ok:
            return True, ""
        # Try URL
        ok, _ = self.validate_url(value)
        if ok:
            return True, ""
        # Try hostname
        ok, reason = self.validate_hostname(value)
        return ok, reason

    def sanitize_arg(self, value: str) -> str:
        """Strip dangerous characters from a single argument."""
        # Remove null bytes, backticks, $(), shell operators
        sanitized = value.replace("\x00", "")
        sanitized = re.sub(r"[`$|;&><]", "", sanitized)
        sanitized = re.sub(r"\.\./\.\./", "", sanitized)
        return sanitized.strip()

    def sanitize_args(self, args: list[str]) -> list[str]:
        """Sanitise a list of arguments."""
        return [self.sanitize_arg(a) for a in args]

    def has_injection(self, value: str) -> tuple[bool, str]:
        """Check a string for injection patterns."""
        for name, pattern in _INJECTION_PATTERNS:
            if pattern.search(value):
                return True, name
        return False, ""

    def check_args_injection(self, args: list[str]) -> tuple[bool, str]:
        """Check a list of arguments for injection patterns."""
        full = " ".join(args)
        return self.has_injection(full)


# ═══════════════════════════════════════════════════════════════════════════
# SecretRedactor
# ═══════════════════════════════════════════════════════════════════════════

_REDACT_PLACEHOLDER = "[REDACTED]"

_REDACT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # API keys
    ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "aws_secret_key",
        re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*\S+"),
    ),
    ("bearer_token", re.compile(r"(?i)Bearer\s+[A-Za-z0-9_.~+/=-]{20,}")),
    ("basic_auth", re.compile(r"(?i)Basic\s+[A-Za-z0-9+/=]{10,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    (
        "generic_api_key",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_.~+/=-]{16,}['\"]?"
        ),
    ),
    # Passwords in URLs
    ("url_password", re.compile(r"://[^:]+:([^@]{3,})@")),
    # Private key markers
    ("private_key", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
    # Generic secret-like key=value
    (
        "secret_kv",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|token|auth|credential|private[_-]?key)\s*[=:]\s*\S+",
        ),
    ),
    # JWT tokens
    (
        "jwt_token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    ),
    # Slack tokens
    ("slack_token", re.compile(r"xox[bporas]-[0-9A-Za-z-]+")),
    # Gemini / Google API keys
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
    """Redacts secrets from text output and dictionaries."""

    def redact(self, text: str) -> str:
        """Return *text* with all detected secrets replaced by [REDACTED]."""
        result = text
        for _name, pattern in _REDACT_PATTERNS:
            result = pattern.sub(_REDACT_PLACEHOLDER, result)
        return result

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Deep-copy *data* and redact all string values that look secret."""
        out = copy.deepcopy(data)
        self._walk_dict(out)
        return out

    def is_sensitive_key(self, key: str) -> bool:
        """Return True if *key* looks like it stores a secret."""
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


# ═══════════════════════════════════════════════════════════════════════════
# DangerAnalyzer
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class DangerReport:
    """Assessment of how dangerous a command is."""

    is_dangerous: bool
    severity: str  # 'critical' | 'high' | 'medium' | 'low' | 'safe'
    reasons: list[str] = field(default_factory=list)
    recommendation: str = ""
    matched_patterns: list[str] = field(default_factory=list)

    @property
    def requires_confirmation(self) -> bool:
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
        re.compile(r"\bchmod\s+777\s+/", re.I),
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
        re.compile(r"\bcurl\b.*\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.I),
        "high",
        "Pipe curl to shell",
    ),
    (
        re.compile(r"\bwget\b.*\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.I),
        "high",
        "Pipe wget to shell",
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
    (re.compile(r"\bformat\s+[a-zA-Z]:", re.I), "medium", "Windows format disk"),
    # ── LOW ──
    (re.compile(r"\bchmod\b", re.I), "low", "Permission change (chmod)"),
    (re.compile(r"\bchown\b", re.I), "low", "Ownership change (chown)"),
    (re.compile(r"\bsudo\b", re.I), "low", "Elevated privileges (sudo)"),
    (re.compile(r"\bcrontab\b", re.I), "low", "Crontab modification"),
]

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}


class DangerAnalyzer:
    """Classifies commands by destructiveness before execution."""

    def analyze(self, command: str) -> DangerReport:
        """Analyze a command string and return a danger report."""
        if not command or not command.strip():
            return DangerReport(is_dangerous=False, severity="safe")

        reasons: list[str] = []
        matched: list[str] = []
        max_severity = "safe"

        for pattern, severity, description in _DANGER_PATTERNS:
            if pattern.search(command):
                reasons.append(f"[{severity.upper()}] {description}")
                matched.append(pattern.pattern)
                if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(
                    max_severity, 0
                ):
                    max_severity = severity

        is_dangerous = max_severity != "safe"
        recommendation = ""
        if max_severity == "critical":
            recommendation = (
                "⛔ BLOCK — This command is destructive and should NOT be executed."
            )
        elif max_severity == "high":
            recommendation = "⚠️  CONFIRM — This command is high-risk. Require explicit user confirmation."
        elif max_severity == "medium":
            recommendation = "⚡ CAUTION — Review this command before execution."
        elif max_severity == "low":
            recommendation = "ℹ️  INFO — Low-risk operation; proceed with awareness."

        return DangerReport(
            is_dangerous=is_dangerous,
            severity=max_severity,
            reasons=reasons,
            recommendation=recommendation,
            matched_patterns=matched,
        )

    def format_warning(
        self, report: DangerReport, console: Console | None = None
    ) -> None:
        """Print a formatted danger warning to a Rich console."""
        if not report.is_dangerous:
            return
        c = console or Console()
        color_map = {
            "critical": "bold bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
        }
        style = color_map.get(report.severity, "white")
        icon_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
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


# ═══════════════════════════════════════════════════════════════════════════
# Module-level singletons
# ═══════════════════════════════════════════════════════════════════════════

validator = InputValidator()
redactor = SecretRedactor()
danger_analyzer = DangerAnalyzer()
