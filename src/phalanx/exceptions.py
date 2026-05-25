"""Phalanx custom exceptions with rich error messages and context."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = [
    "PhalanxException",
    "ValidationError",
    "ExecutionError",
    "PlanningError",
    "SafetyError",
    "ToolNotFoundError",
    "CredentialError",
    "ConfigurationError",
    "NetworkError",
    "TimeoutError",
    "CircuitBreakerOpen",
    "MaxRetriesExceeded",
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


class PhalanxException(Exception):
    """Base exception for all Phalanx errors."""

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


class ValidationError(PhalanxException):
    """Input validation failed."""

    pass


class ExecutionError(PhalanxException):
    """Tool execution failed."""

    pass


class PlanningError(PhalanxException):
    """Task planning failed."""

    pass


class SafetyError(PhalanxException):
    """Safety validation blocked operation."""

    pass


class ToolNotFoundError(PhalanxException):
    """Tool not found in registry or PATH."""

    pass


class CredentialError(PhalanxException):
    """Credential management error."""

    pass


class ConfigurationError(PhalanxException):
    """Configuration error."""

    pass


class NetworkError(PhalanxException):
    """Network operation failed."""

    pass


class TimeoutError(PhalanxException):
    """Operation timed out."""

    pass


class CircuitBreakerOpen(PhalanxException):
    """Circuit breaker is open; service temporarily unavailable."""

    pass


class MaxRetriesExceeded(PhalanxException):
    """Maximum retry attempts exceeded."""

    pass


class PermissionDeniedError(PhalanxException):
    """User rejected a permission gate (exit code 2)."""

    pass


class ProviderError(PhalanxException):
    """AI provider error / timeout (exit code 4)."""

    pass


# Exit codes as documented in Chapter 3.3:
# Check most specific types first, then fall back to base PhalanxException.
_EXIT_CODE_RULES: list[tuple[type[PhalanxException], int]] = [
    (PermissionDeniedError, 2),
    (SafetyError, 2),
    (ToolNotFoundError, 3),
    (ProviderError, 4),
    (TimeoutError, 4),
    (CircuitBreakerOpen, 4),
    (ExecutionError, 1),
    (ValidationError, 1),
    (PlanningError, 1),
    (ConfigurationError, 1),
    (NetworkError, 1),
    (MaxRetriesExceeded, 1),
    (CredentialError, 1),
    (PhalanxException, 1),
]


def exit_code_for(exc: PhalanxException) -> int:
    """Return the documented exit code (Chapter 3.3) for a PhalanxException.

    0 = Success
    1 = Execution error
    2 = Permission denied
    3 = Tool not found
    4 = LLM error / timeout
    """
    for exc_type, code in _EXIT_CODE_RULES:
        if isinstance(exc, exc_type):
            return code
    return 1
