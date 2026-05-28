# SPDX-License-Identifier: AGPL-3.0-or-later

"""Error recovery, retry logic, and fallback strategies."""

from __future__ import annotations

import random

from .steps import _RETRY_BACKOFF_FACTOR, _RETRY_BASE_DELAY, _RETRY_MAX_DELAY

TRANSIENT_INDICATORS = [
    "timeout",
    "temporarily unavailable",
    "connection refused",
    "connection reset",
    "connection timeout",
    "temporarily",
    "busy",
    "try again",
    "server is unavailable",
    "gateway timeout",
    "internal server error",
    "service unavailable",
    "too many requests",
    "rate limit",
    "rate_limit",
    "server error",
    "bad gateway",
]


def is_transient_error(error: str) -> bool:
    """Check if error is transient and retryable."""
    error_lower = str(error).lower()
    return any(indicator in error_lower for indicator in TRANSIENT_INDICATORS)


async def calculate_backoff_delay(attempt: int) -> float:
    """Calculate exponential backoff delay with jitter."""
    delay = _RETRY_BASE_DELAY * (_RETRY_BACKOFF_FACTOR**attempt)
    delay = min(delay, _RETRY_MAX_DELAY)
    jitter = delay * random.uniform(0.9, 1.1)
    return jitter
