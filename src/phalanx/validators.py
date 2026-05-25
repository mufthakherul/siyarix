"""Input validation utilities with comprehensive checks."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .exceptions import ValidationError, ErrorContext, ErrorSeverity

__all__ = [
    "validate_target",
    "validate_port",
    "validate_cidr",
    "validate_url",
    "validate_hostname",
    "validate_email",
    "validate_api_key",
    "validate_not_empty",
    "validate_min_length",
    "validate_max_length",
    "validate_pattern",
    "sanitize_target",
]


def validate_not_empty(value: str, field_name: str = "value") -> None:
    """Validate that string is not empty."""
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
    """Validate minimum length."""
    if len(value) < min_len:
        raise ValidationError(
            f"{field_name} must be at least {min_len} characters",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                component="validator",
            ),
        )


def validate_max_length(value: str, max_len: int, field_name: str = "value") -> None:
    """Validate maximum length."""
    if len(value) > max_len:
        raise ValidationError(
            f"{field_name} must not exceed {max_len} characters",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                component="validator",
            ),
        )


def validate_pattern(
    value: str,
    pattern: str | re.Pattern[str],
    field_name: str = "value",
) -> None:
    """Validate against regex pattern."""
    if isinstance(pattern, str):
        pattern = re.compile(pattern)

    if not pattern.match(value):
        raise ValidationError(
            f"{field_name} does not match required pattern",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                technical_details={"pattern": pattern.pattern},
                component="validator",
            ),
        )


def validate_port(port: int | str) -> None:
    """Validate port number."""
    try:
        port_num = int(port) if isinstance(port, str) else port
    except (ValueError, TypeError):
        raise ValidationError(
            f"Invalid port: {port}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="Port must be a number between 1 and 65535",
                component="validator",
            ),
        )

    if not 1 <= port_num <= 65535:
        raise ValidationError(
            f"Port out of range: {port_num}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="Port must be between 1 and 65535",
                component="validator",
            ),
        )


def validate_cidr(cidr: str) -> None:
    """Validate CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValidationError(
            f"Invalid CIDR: {cidr}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="CIDR must be in format: 192.168.1.0/24",
                technical_details={"error": str(e)},
                component="validator",
            ),
            cause=e,
        )


def validate_hostname(hostname: str) -> None:
    """Validate hostname (RFC 1123)."""
    # Remove port if present
    host = hostname.split(":")[0]

    # Pattern for valid hostname
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$"

    if not re.match(pattern, host):
        raise ValidationError(
            f"Invalid hostname: {hostname}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="Hostname must be valid (e.g., example.com, host.example.com)",
                component="validator",
            ),
        )


def validate_url(url: str) -> None:
    """Validate URL format."""
    pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    if not re.match(pattern, url, re.IGNORECASE):
        raise ValidationError(
            f"Invalid URL: {url}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                user_message="URL must start with http:// or https://",
                component="validator",
            ),
        )


def validate_email(email: str) -> None:
    """Validate email address."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        raise ValidationError(
            f"Invalid email: {email}",
            context=ErrorContext(
                severity=ErrorSeverity.ERROR,
                component="validator",
            ),
        )


def validate_api_key(api_key: str, min_length: int = 20) -> None:
    """Validate API key format."""
    validate_not_empty(api_key, "API key")
    validate_min_length(api_key, min_length, "API key")


def validate_target(target: str) -> dict[str, Any]:
    """Validate target and return metadata.

    Returns:
        dict with keys: type (ipv4|ipv6|cidr|hostname|url), normalized_target

    Raises:
        ValidationError: If target is invalid
    """
    target = target.strip()
    validate_not_empty(target, "target")

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

    raise ValidationError(
        f"Invalid target: {target}",
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


def sanitize_target(target: str) -> str:
    """Sanitize target by removing dangerous characters."""
    # Remove shell metacharacters
    dangerous_chars = ";|&><'\"$`()\n"
    for char in dangerous_chars:
        target = target.replace(char, "")

    return target.strip()
