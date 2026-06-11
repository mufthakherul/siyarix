# SPDX-License-Identifier: AGPL-3.0-or-later

"""Input validation utilities with comprehensive checks.

NOTE: This differs from ``validator.py`` which handles self-validation,
verification, and recovery. This module contains input format validators
(targets, ports, URLs, etc.) for user-supplied data.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .exceptions import ErrorContext, ErrorSeverity, ValidationError

__all__ = [
    "validate_target",
    "validate_url",
    "validate_hostname",
    "validate_not_empty",
    "validate_min_length",
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



