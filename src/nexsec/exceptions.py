"""NexSec custom exceptions with rich error messages and context."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = [
    "NexSecException",
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


class NexSecException(Exception):
    """Base exception for all NexSec errors."""

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


class ValidationError(NexSecException):
    """Input validation failed."""
    pass


class ExecutionError(NexSecException):
    """Tool execution failed."""
    pass


class PlanningError(NexSecException):
    """Task planning failed."""
    pass


class SafetyError(NexSecException):
    """Safety validation blocked operation."""
    pass


class ToolNotFoundError(NexSecException):
    """Tool not found in registry or PATH."""
    pass


class CredentialError(NexSecException):
    """Credential management error."""
    pass


class ConfigurationError(NexSecException):
    """Configuration error."""
    pass


class NetworkError(NexSecException):
    """Network operation failed."""
    pass


class TimeoutError(NexSecException):
    """Operation timed out."""
    pass


class CircuitBreakerOpen(NexSecException):
    """Circuit breaker is open; service temporarily unavailable."""
    pass


class MaxRetriesExceeded(NexSecException):
    """Maximum retry attempts exceeded."""
    pass
