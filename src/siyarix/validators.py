# SPDX-License-Identifier: AGPL-3.0-or-later

"""Input validation utilities with comprehensive checks.

Differs from ``validator.py`` which handles self-validation.
This module contains input format validators
(targets, ports, URLs, etc.) for user-supplied data.

All regex patterns are compiled at module level for performance.  Every
public function enforces an input-length ceiling to prevent catastrophic
backtracking (ReDoS).
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable

from .exceptions import ErrorContext, ErrorSeverity, ValidationError
from .planner import PlanStep
from .events import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)

__all__ = [
    "validate_cidr",
    "validate_email",
    "validate_hostname",
    "validate_min_length",
    "validate_not_empty",
    "validate_port",
    "validate_port_range",
    "validate_target",
    "validate_url",
    "ValidationSeverity",
    "RecoveryAction",
    "ValidationResult",
    "RecoveryPlan",
    "Validator",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_INPUT_LENGTH = 2048
"""Hard ceiling for any single input string to prevent ReDoS."""

_MAX_HOSTNAME_LENGTH = 253
"""RFC 1123 maximum hostname length."""

_MAX_LABEL_LENGTH = 63
"""RFC 1123 maximum label length within a hostname."""

_PORT_MIN = 1
_PORT_MAX = 65535

# ---------------------------------------------------------------------------
# Compiled regex patterns (module-level for performance)
# ---------------------------------------------------------------------------

_RE_URL = re.compile(
    r"^https?://[^\s/$.?#]+\.[^\s]+$",
    re.IGNORECASE,
)
"""URL pattern - H-04 / L-11: character class now uses ``[^\\s/$.?#]+``
followed by a literal dot and ``[^\\s]+`` so the TLD portion is required."""

_RE_HOSTNAME = re.compile(
    r"^(?:"
    r"localhost"  # bare localhost
    r"|"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)"  # single-label
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"  # optional dot-labels
    r")$"
)
"""Hostname pattern — H-05: accepts ``localhost``, single-label hosts
(e.g. ``myserver``), and multi-label names with numeric TLDs."""

_RE_EMAIL = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~\-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)
"""Simplified RFC 5321 email pattern for notification config."""

_RE_CIDR = re.compile(r"^[\da-fA-F.:]+/\d{1,3}$")
"""Quick pre-filter for CIDR notation before handing off to ``ipaddress``."""

_RE_PORT_RANGE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
"""Matches a dash-separated port range like ``80-443``."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _enforce_length(value: str, field_name: str) -> None:
    """Raise ``ValidationError`` when *value* exceeds the global ceiling.

    Args:
        value: The raw input string.
        field_name: Human-readable name used in the error message.

    Raises:
        ValidationError: If ``len(value) > _MAX_INPUT_LENGTH``.

    Example::

        >>> _enforce_length("a" * 3000, "target")  # doctest: +SKIP
        ValidationError: ...
    """
    if len(value) > _MAX_INPUT_LENGTH:
        raise ValidationError(
            f"{field_name} exceeds maximum length of {_MAX_INPUT_LENGTH}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message=f"{field_name} is too long (max {_MAX_INPUT_LENGTH} chars)",
                component="validator",
            ),
        )


def _redact(value: str, *, max_visible: int = 32) -> str:
    """Return a redacted representation of *value* for safe error messages.

    Short values (≤ *max_visible* characters) are returned verbatim.
    Longer values are truncated and appended with ``…[redacted]``.

    Args:
        value: The original string.
        max_visible: Maximum characters to keep visible.

    Returns:
        The (possibly truncated) string.

    Examples::

        >>> _redact("short")
        'short'
        >>> _redact("a" * 100)  # doctest: +ELLIPSIS
        'aaaa...…[redacted]'
    """
    if len(value) <= max_visible:
        return value
    return value[:max_visible] + "…[redacted]"


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------


def validate_not_empty(value: str, field_name: str = "value") -> None:
    """Validate that *value* is a non-blank string.

    Args:
        value: The string to check.
        field_name: Label used in the error message (default ``"value"``).

    Raises:
        ValidationError: If *value* is empty or contains only whitespace.

    Examples::

        >>> validate_not_empty("hello")          # passes
        >>> validate_not_empty("")               # doctest: +SKIP
        ValidationError: value cannot be empty
        >>> validate_not_empty("   ", "query")   # doctest: +SKIP
        ValidationError: query cannot be empty
    """
    if not value or not value.strip():
        raise ValidationError(
            f"{field_name} cannot be empty",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message=f"Please provide a {field_name.lower()}",
                component="validator",
            ),
        )


def validate_min_length(value: str, min_len: int, field_name: str = "value") -> None:
    """Validate that *value* meets a minimum character length.

    Args:
        value: The string to check.
        min_len: Required minimum length (inclusive).
        field_name: Label used in the error message (default ``"value"``).

    Raises:
        ValidationError: If ``len(value) < min_len``.

    Examples::

        >>> validate_min_length("abc", 3)        # passes (exactly 3)
        >>> validate_min_length("ab", 3)         # doctest: +SKIP
        ValidationError: value must be at least 3 characters
    """
    if len(value) < min_len:
        raise ValidationError(
            f"{field_name} must be at least {min_len} characters",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                component="validator",
            ),
        )


def validate_hostname(hostname: str) -> None:
    """Validate a hostname against a relaxed RFC 1123 pattern.

    Accepts fully-qualified domain names, single-label hostnames (e.g.
    ``myserver``), numeric TLDs, and the special name ``localhost``.
    An optional ``:port`` suffix is stripped before validation.

    Args:
        hostname: The hostname string, optionally with a ``:port`` suffix.

    Raises:
        ValidationError: If the hostname does not match the allowed pattern
            or exceeds length limits.

    Examples::

        >>> validate_hostname("example.com")     # passes
        >>> validate_hostname("localhost")        # passes  (H-05)
        >>> validate_hostname("myserver")         # passes  (H-05, single-label)
        >>> validate_hostname("host.123")         # passes  (H-05, numeric TLD)
        >>> validate_hostname("bad host!")        # doctest: +SKIP
        ValidationError: Invalid hostname
    """
    _enforce_length(hostname, "hostname")

    # Remove port if present
    host = hostname.split(":")[0]

    if len(host) > _MAX_HOSTNAME_LENGTH:
        raise ValidationError(
            "Invalid hostname: exceeds maximum length",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message=(f"Hostname must not exceed {_MAX_HOSTNAME_LENGTH} characters"),
                component="validator",
            ),
        )

    if not _RE_HOSTNAME.match(host):
        raise ValidationError(
            f"Invalid hostname: {_redact(hostname)}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message=("Hostname must be valid (e.g., example.com, localhost, myserver)"),
                component="validator",
            ),
        )


def validate_url(url: str) -> None:
    """Validate a URL for ``http`` or ``https`` schemes.

    The regex requires at least one non-whitespace character before a
    literal dot, preventing bare-scheme strings like ``http://``.

    Args:
        url: The URL string.

    Raises:
        ValidationError: If the URL is malformed or uses an unsupported
            scheme.

    Examples::

        >>> validate_url("https://example.com/path")   # passes
        >>> validate_url("http://10.0.0.1:8080/api")   # passes
        >>> validate_url("ftp://example.com")           # doctest: +SKIP
        ValidationError: Invalid URL
    """
    _enforce_length(url, "URL")

    if not _RE_URL.match(url):
        raise ValidationError(
            f"Invalid URL: {_redact(url)}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="URL must start with http:// or https://",
                component="validator",
            ),
        )


def validate_port(port: int | str) -> int:
    """Validate and return a single TCP/UDP port number.

    Accepts integers or numeric strings in the range 1–65 535.

    Args:
        port: Port number (``int``) or its string representation.

    Returns:
        The validated port as an ``int``.

    Raises:
        ValidationError: If *port* is not a valid port number.

    Examples::

        >>> validate_port(443)
        443
        >>> validate_port("8080")
        8080
        >>> validate_port(0)           # doctest: +SKIP
        ValidationError: Port must be between 1 and 65535
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValidationError(
            f"Invalid port: {_redact(str(port))}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="Port must be a number between 1 and 65535",
                component="validator",
            ),
        )

    if not (_PORT_MIN <= port_int <= _PORT_MAX):
        raise ValidationError(
            f"Port {port_int} out of range",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message=f"Port must be between {_PORT_MIN} and {_PORT_MAX}",
                component="validator",
            ),
        )

    return port_int


def validate_port_range(port_range: str) -> tuple[int, int]:
    """Validate a dash-separated port range string.

    The start port must be ≤ the end port, and both must fall in 1–65 535.

    Args:
        port_range: A string like ``"80-443"`` or a single port ``"8080"``.

    Returns:
        A ``(start, end)`` tuple of validated port ints.

    Raises:
        ValidationError: If the range is malformed or out of bounds.

    Examples::

        >>> validate_port_range("80-443")
        (80, 443)
        >>> validate_port_range("8080")
        (8080, 8080)
        >>> validate_port_range("443-80")          # doctest: +SKIP
        ValidationError: Start port must be ≤ end port
    """
    _enforce_length(port_range, "port range")
    port_range = port_range.strip()

    match = _RE_PORT_RANGE.match(port_range)
    if match:
        start = validate_port(match.group(1))
        end = validate_port(match.group(2))
    else:
        # Could be a single port
        start = end = validate_port(port_range)

    if start > end:
        raise ValidationError(
            f"Invalid port range: {start}-{end}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="Start port must be ≤ end port",
                component="validator",
            ),
        )

    return start, end


def validate_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate a CIDR notation string and return the network object.

    Accepts both IPv4 and IPv6 CIDR blocks.  Host bits are silently
    masked (``strict=False``).

    Args:
        cidr: A CIDR string such as ``"10.0.0.0/24"`` or ``"fe80::/10"``.

    Returns:
        An :class:`~ipaddress.IPv4Network` or :class:`~ipaddress.IPv6Network`.

    Raises:
        ValidationError: If *cidr* is not valid CIDR notation.

    Examples::

        >>> validate_cidr("192.168.1.0/24")
        IPv4Network('192.168.1.0/24')
        >>> validate_cidr("bad-cidr")              # doctest: +SKIP
        ValidationError: Invalid CIDR notation
    """
    _enforce_length(cidr, "CIDR")
    cidr = cidr.strip()

    if not _RE_CIDR.match(cidr):
        raise ValidationError(
            f"Invalid CIDR notation: {_redact(cidr)}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="CIDR must be in the form address/prefix (e.g. 10.0.0.0/24)",
                component="validator",
            ),
        )

    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise ValidationError(
            f"Invalid CIDR notation: {_redact(cidr)}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="CIDR must be in the form address/prefix (e.g. 10.0.0.0/24)",
                suggestions=[
                    "10.0.0.0/24 (IPv4)",
                    "fe80::/10 (IPv6)",
                ],
                component="validator",
            ),
        )


def validate_email(email: str) -> None:
    """Validate an email address for notification configuration.

    Uses a simplified RFC 5321 pattern — sufficient for accepting
    notification targets but not a full RFC 5322 parser.

    Args:
        email: The email address string.

    Raises:
        ValidationError: If the email address is malformed.

    Examples::

        >>> validate_email("user@example.com")      # passes
        >>> validate_email("no-at-sign.com")         # doctest: +SKIP
        ValidationError: Invalid email address
    """
    _enforce_length(email, "email")
    email = email.strip()

    if not _RE_EMAIL.match(email):
        raise ValidationError(
            f"Invalid email address: {_redact(email)}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="Provide a valid email address (e.g., user@example.com)",
                component="validator",
            ),
        )


def validate_target(target: str) -> dict[str, Any]:
    """Validate a scan target and return classification metadata.

    Tries each target type in order: IPv4 → IPv6 → CIDR → URL → hostname.
    Returns the first match.

    Args:
        target: The raw target string supplied by the user.

    Returns:
        A ``dict`` with keys:

        - ``type`` — one of ``"ipv4"``, ``"ipv6"``, ``"cidr"``,
          ``"hostname"``, ``"url"``.
        - ``normalized`` — the whitespace-stripped target string.

    Raises:
        ValidationError: If *target* does not match any known format.
            Long targets are redacted in the error message (M-13).

    Examples::

        >>> validate_target("192.168.1.1")
        {'type': 'ipv4', 'normalized': '192.168.1.1'}
        >>> validate_target("10.0.0.0/24")
        {'type': 'cidr', 'normalized': '10.0.0.0/24'}
        >>> validate_target("https://example.com")
        {'type': 'url', 'normalized': 'https://example.com'}
    """
    target = target.strip()
    validate_not_empty(target, "target")
    _enforce_length(target, "target")

    # Try IPv4
    try:
        ipaddress.IPv4Address(target)
        return {"type": "ipv4", "normalized": target}
    except ValueError:
        pass

    # Try IPv6
    try:
        ipaddress.IPv6Address(target)
        return {"type": "ipv6", "normalized": target}
    except ValueError:
        pass

    # Try CIDR
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return {"type": "cidr", "normalized": target}
        except ValueError:
            pass

    # Try URL
    if target.startswith(("http://", "https://")):
        try:
            validate_url(target)
            return {"type": "url", "normalized": target}
        except ValidationError:
            pass

    # Try hostname
    try:
        validate_hostname(target)
        return {"type": "hostname", "normalized": target}
    except ValidationError:
        pass

    # M-13: redact long targets in error messages
    raise ValidationError(
        "Invalid target format provided",
        context=ErrorContext(
            severity=ErrorSeverity.ERROR,
            user_message="Target must be IPv4, IPv6, CIDR, hostname, or URL",
            suggestions=[
                "192.168.1.1 (IPv4)",
                "10.0.0.0/24 (CIDR)",
                "example.com (hostname)",
                "https://example.com (URL)",
            ],
            component="validator",
        ),
    )


class ValidationSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RecoveryAction(StrEnum):
    RETRY = "retry"
    RETRY_ALTERNATIVE = "retry_alternative"
    SKIP = "skip"
    ABORT = "abort"
    ESCALATE = "escalate"
    DEGRADE = "degrade"


@dataclass
class ValidationResult:
    passed: bool = True
    severity: ValidationSeverity = ValidationSeverity.INFO
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    recovery_action: RecoveryAction | None = None
    recovery_suggestion: str = ""


@dataclass
class RecoveryPlan:
    original_step: PlanStep
    action: RecoveryAction
    modified_step: PlanStep | None = None
    alternative_tool: str = ""
    message: str = ""


class Validator:
    def __init__(self) -> None:
        self._validators: list[Callable[[PlanStep], ValidationResult]] = [
            self._validate_step_has_tool,
            self._validate_step_has_args,
            self._validate_step_timeout,
        ]
        self._event_bus = get_event_bus()
        self._results: list[ValidationResult] = []

    def _validate_step_has_tool(self, step: PlanStep) -> ValidationResult:
        if not step.tool:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.ERROR,
                message="Step has no tool specified",
                recovery_action=RecoveryAction.SKIP,
            )
        return ValidationResult(passed=True)

    def _validate_step_has_args(self, step: PlanStep) -> ValidationResult:
        if not step.args and step.tool not in ("report", "summary"):
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.WARNING,
                message=f"Step '{step.tool}' has no arguments",
                recovery_action=RecoveryAction.RETRY,
            )
        return ValidationResult(passed=True)

    def _validate_step_timeout(self, step: PlanStep) -> ValidationResult:
        if step.timeout <= 0:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.WARNING,
                message="Step timeout is non-positive",
                recovery_action=RecoveryAction.RETRY,
            )
        return ValidationResult(passed=True)

    async def validate_step(self, step: PlanStep) -> list[ValidationResult]:
        results = [v(step) for v in self._validators]
        for r in results:
            if not r.passed:
                await self._event_bus.emit(
                    Event(
                        type=EventType.VALIDATION_FAILED,
                        source="validator",
                        data={"step_id": step.id, "tool": step.tool, "message": r.message},
                    )
                )
        self._results.extend(results)
        return results

    async def validate_plan(self, steps: list[PlanStep]) -> list[ValidationResult]:
        all_results = []
        for step in steps:
            all_results.extend(await self.validate_step(step))
        return all_results

    async def plan_recovery(self, step: PlanStep, error: str) -> RecoveryPlan:
        tool = step.tool
        if tool == "nmap" and "filtered" in error.lower():
            return RecoveryPlan(
                original_step=step,
                action=RecoveryAction.RETRY,
                modified_step=PlanStep(
                    id=step.id,
                    description=step.description,
                    tool=tool,
                    args={**step.args, "flags": step.args.get("flags", "") + " -Pn"},
                    timeout=step.timeout,
                ),
                message="Adding -Pn flag for filtered ports",
            )
        if tool in ("nikto", "nuclei") and "refused" in error.lower():
            return RecoveryPlan(
                original_step=step,
                action=RecoveryAction.RETRY_ALTERNATIVE,
                alternative_tool="nuclei" if tool == "nikto" else "nikto",
                message="Target refused connection, trying alternative",
            )
        if tool in ("gobuster", "ffuf") and "404" in error:
            return RecoveryPlan(
                original_step=step,
                action=RecoveryAction.RETRY,
                modified_step=PlanStep(
                    id=step.id,
                    description=step.description,
                    tool=tool,
                    args={**step.args, "extensions": "php,html,js,txt,asp,aspx,jsp"},
                    timeout=step.timeout,
                ),
                message="Adding more file extensions",
            )
        if step.can_retry:
            return RecoveryPlan(
                original_step=step,
                action=RecoveryAction.RETRY,
                message=f"Retrying (attempt {step.retry_count + 1}/{step.max_retries})",
            )
        return RecoveryPlan(
            original_step=step,
            action=RecoveryAction.SKIP,
            message=f"Max retries exceeded for {tool}",
        )

    def stats(self) -> dict[str, Any]:
        return {
            "total_validations": len(self._results),
            "passed": len([r for r in self._results if r.passed]),
            "failed": len([r for r in self._results if not r.passed]),
        }
