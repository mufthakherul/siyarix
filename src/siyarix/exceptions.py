# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix custom exceptions with rich error messages and context.

Every public exception inherits from :class:`SiyarixException` so that
callers can use a single ``except SiyarixException`` clause when they
don't care about the specific failure mode.  Each concrete subclass maps
to a documented CLI exit code via :func:`exit_code_for`.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = [
    "SiyarixException",
    "ValidationError",
    "ExecutionError",
    "PlanningError",
    "SafetyError",
    "ToolNotFoundError",
    "CredentialError",
    "ConfigurationError",
    "NetworkError",
    "SiyarixTimeoutError",
    "CircuitBreakerOpen",
    "MaxRetriesExceeded",
    "ErrorSeverity",
    "ErrorContext",
    "PermissionDeniedError",
    "ProviderError",
    "BudgetExceededError",
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


class ExecutionError(SiyarixException):
    """Tool execution failed."""

    pass


class PlanningError(SiyarixException):
    """Task planning failed."""

    pass


class SafetyError(SiyarixException):
    """A configured safety rule was violated."""

    pass


class BudgetExceededError(SiyarixException):
    """The session exceeded its allowed token or cost budget."""

    pass


class ToolNotFoundError(SiyarixException):
    """Tool not found in registry or PATH."""

    pass


class CredentialError(SiyarixException):
    """Credential management error."""

    pass


class ConfigurationError(SiyarixException):
    """Configuration error."""

    pass


class NetworkError(SiyarixException):
    """Network operation failed."""

    pass


class SiyarixTimeoutError(SiyarixException):
    """Operation timed out.

    .. note::
        Previously named ``TimeoutError``, which shadowed the Python
        built-in.  The old name is still importable but emits a
        :class:`DeprecationWarning`.
    """

    pass


class _DeprecatedTimeoutErrorMeta(type):
    """Metaclass that emits a deprecation warning on instantiation."""

    def __call__(cls, *args: Any, **kwargs: Any) -> SiyarixTimeoutError:
        warnings.warn(
            "siyarix.exceptions.TimeoutError is deprecated and shadows a "
            "Python built-in. Use SiyarixTimeoutError instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return SiyarixTimeoutError(*args, **kwargs)


class TimeoutError(  # noqa: A001  — intentional deprecated alias
    SiyarixTimeoutError,
    metaclass=_DeprecatedTimeoutErrorMeta,
):
    """**Deprecated** — use :class:`SiyarixTimeoutError` instead."""

    pass


class CircuitBreakerOpen(SiyarixException):
    """Circuit breaker is open; service temporarily unavailable."""

    pass


class MaxRetriesExceeded(SiyarixException):
    """Maximum retry attempts exceeded."""

    pass


class PermissionDeniedError(SiyarixException):
    """User rejected a permission gate (exit code 2)."""

    pass


class ProviderError(SiyarixException):
    """AI provider error / timeout (exit code 4)."""

    pass


# Exit codes as documented in Chapter 3.3.
# Dict provides O(1) lookup by exact type; the fallback path walks the MRO
# so subclass specificity is preserved without a linear scan.
_EXIT_CODE_MAP: dict[type[SiyarixException], int] = {
    PermissionDeniedError: 2,
    SafetyError: 2,
    ToolNotFoundError: 3,
    ProviderError: 4,
    SiyarixTimeoutError: 4,
    CircuitBreakerOpen: 4,
    ExecutionError: 1,
    ValidationError: 1,
    PlanningError: 1,
    ConfigurationError: 1,
    NetworkError: 1,
    MaxRetriesExceeded: 1,
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
