# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix custom exceptions with rich error messages and context.

Every public exception inherits from :class:`SiyarixException` so that
callers can use a single ``except SiyarixException`` clause when they
don't care about the specific failure mode.  Each concrete subclass maps
to a documented CLI exit code via :func:`exit_code_for`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = [
    "SiyarixException",
    "ValidationError",
    "ErrorSeverity",
    "ErrorContext",
    "PermissionDeniedError",
    "BudgetExceededError",
    "ToolNotFoundError",
    "ToolExecutionError",
    "LLMProviderError",
    "ConfigError",
    "CredentialError",
    "exit_code_for",
]


class ErrorSeverity(StrEnum):
    """Error severity levels."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ErrorContext:
    """Rich error context for better diagnostics."""

    severity: ErrorSeverity = ErrorSeverity.ERROR
    user_message: str = ""
    technical_details: dict[str, Any] | None = None
    suggestions: list[str] | None = None
    component: str = ""


class SiyarixException(Exception):
    """Base exception for all Siyarix errors.

    Parameters
    ----------
    message:
        Human-readable description of what went wrong.
    context:
        Optional :class:`ErrorContext` carrying severity, component name,
        and actionable suggestions.
    cause:
        Optional upstream exception that triggered this error.
    """

    def __init__(
        self,
        message: str,
        context: ErrorContext | None = None,
        cause: Exception | None = None,
    ) -> None:
        self.message = message
        self.context = context or ErrorContext()
        self.cause = cause
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format complete error message with context."""
        msg = self.message
        if self.context.component:
            msg = f"[{self.context.component}] {msg}"
        if self.context.user_message:
            msg += f"\n→ {self.context.user_message}"
        if self.context.technical_details:
            msg += f"\nDetails: {self.context.technical_details}"
        if self.context.suggestions:
            msg += "\nTry:\n" + "\n".join(f"  • {s}" for s in self.context.suggestions)
        return msg


class ValidationError(SiyarixException):
    """Input validation failed."""

    pass


class BudgetExceededError(SiyarixException):
    """The session exceeded its allowed token or cost budget."""

    pass


class PermissionDeniedError(SiyarixException):
    """User rejected a permission gate (exit code 2)."""

    pass


class ToolNotFoundError(SiyarixException):
    """Requested tool is not registered or not on PATH (exit code 3)."""

    pass


class ToolExecutionError(SiyarixException):
    """Tool handler raised an exception during execution."""

    pass


class LLMProviderError(SiyarixException):
    """LLM provider returned an error or timed out (exit code 4)."""

    pass


class ConfigError(SiyarixException):
    """Invalid or missing configuration."""

    pass


class CredentialError(SiyarixException):
    """Credential store lookup or storage failed."""

    pass


# Exit codes as documented in Chapter 3.3.
# Dict provides O(1) lookup by exact type; the fallback path walks the MRO
# so subclass specificity is preserved without a linear scan.
_EXIT_CODE_MAP: dict[type[SiyarixException], int] = {
    PermissionDeniedError: 2,
    ToolNotFoundError: 3,
    LLMProviderError: 4,
    BudgetExceededError: 1,
    ValidationError: 1,
    ConfigError: 1,
    ToolExecutionError: 1,
    CredentialError: 1,
    SiyarixException: 1,
}


def exit_code_for(exc: SiyarixException) -> int:
    """Return the documented exit code (Chapter 3.3) for *exc*.

    Exit codes
    ----------
    0 — Success (never returned here; the caller handles success).
    1 — Execution / validation / config error.
    2 — Permission denied / safety block.
    3 — Tool not found.
    4 — LLM provider error or timeout.

    Complexity is O(1) for exact-type hits and O(depth-of-MRO) for
    subclasses that are not explicitly listed.
    """
    # Fast path: exact type match.
    code = _EXIT_CODE_MAP.get(type(exc))
    if code is not None:
        return code
    # Slow path: walk the MRO to find the nearest registered ancestor.
    for ancestor in type(exc).__mro__:
        code = _EXIT_CODE_MAP.get(ancestor)
        if code is not None:
            return code
    return 1
