# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data Loss Prevention (DLP) and Secret Redaction for Siyarix."""

from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Basic patterns for secret detection
SECRET_PATTERNS = {
    "AWS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GCP_KEY": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "SLACK_TOKEN": re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}"),
    "GITHUB_TOKEN": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36}"),
    "GENERIC_BEARER": re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+"),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[a-zA-Z0-9+/=\s]*?(?:-----END [A-Z ]*PRIVATE KEY-----)?", re.DOTALL
    ),
}

PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


class DLPEngine:
    """Scans and redacts sensitive information from tool outputs."""

    def __init__(self, redact_secrets: bool = True, redact_pii: bool = False) -> None:
        self.redact_secrets = redact_secrets
        self.redact_pii = redact_pii

    def redact(self, text: str) -> str:
        """Redact sensitive information from a string."""
        if not text:
            return text

        redacted = text

        if self.redact_secrets:
            for name, pattern in SECRET_PATTERNS.items():
                redacted = pattern.sub(f"[REDACTED {name}]", redacted)

        if self.redact_pii:
            for name, pattern in PII_PATTERNS.items():
                redacted = pattern.sub(f"[REDACTED {name}]", redacted)

        if redacted != text:
            logger.debug("DLP Engine redacted sensitive information.")

        return redacted

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact strings in a dictionary."""
        result: dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, str):
                result[k] = self.redact(v)
            elif isinstance(v, dict):
                result[k] = self.redact_dict(v)
            elif isinstance(v, list):
                result[k] = [self.redact(i) if isinstance(i, str) else i for i in v]
            else:
                result[k] = v
        return result
