# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data Loss Prevention (DLP) and Secret Redaction for Siyarix."""

from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Keep in sync with siyarix.security_hardening._REDACT_PATTERNS (SecretRedactor).
# Named tags are stable for callers/tests; more-specific sk-* forms precede OPENAI_KEY.
SECRET_PATTERNS = {
    "ANTHROPIC_KEY": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "DEEPSEEK_KEY": re.compile(r"sk-ds[A-Za-z0-9_-]{20,}"),
    "OPENAI_KEY": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    "XAI_KEY": re.compile(r"xai-[A-Za-z0-9_-]{20,}"),
    "GROQ_KEY": re.compile(r"gsk_[A-Za-z0-9_-]{16,}"),
    "PROVIDER_KEY_KV": re.compile(
        r"(?i)((?:siyarix_[\w-]+|openai|anthropic|groq|gemini|xai|mistral|ssh)"
        r"[_-]?(?:api[_-]?)?key\s*[=:]\s*)\S+"
    ),
    "AWS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    # Group 1 = key-name prefix (preserved); value is redacted (H-10).
    "AWS_SECRET_KEY": re.compile(r"(?i)(aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*)\S+"),
    "GCP_KEY": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "GCP_SERVICE_ACCOUNT": re.compile(r'"type"\s*:\s*"service_account"'),
    "AZURE_CONNECTION": re.compile(
        r"(?i)(?:DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)=[A-Za-z0-9+/=]+"
    ),
    "MISTRAL_KEY": re.compile(r"(?i)mistral[_-]?api[_-]?key\s*[=:]\s*\S+"),
    "SLACK_TOKEN": re.compile(r"xox[bporas]-[0-9A-Za-z-]+"),
    "GITHUB_TOKEN": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "GENERIC_BEARER": re.compile(r"(?i)Bearer\s+[A-Za-z0-9_.~+/=-]{20,}"),
    "BASIC_AUTH": re.compile(r"(?i)Basic\s+[A-Za-z0-9+/=]{10,}"),
    "GENERIC_API_KEY": re.compile(
        r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_.~+/=-]{16,}['\"]?"
    ),
    # Group 1 = `://user:` prefix; password redacted; `@` kept via lookahead.
    "URL_PASSWORD": re.compile(r"(://[^:/?#]+:)(.{3,})(?=@)"),
    "JWT_TOKEN": re.compile(
        r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"
    ),
    "SECRET_KV": re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|auth|credential|private[_-]?key)\s*[=:]\s*\S+"
    ),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
        r"[a-zA-Z0-9+/=\s]*?"
        r"(?:-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----)?",
        re.DOTALL,
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
        if not isinstance(text, str):
            return text
        if not text:
            return text

        redacted = text

        if self.redact_secrets:
            for name, pattern in SECRET_PATTERNS.items():
                placeholder = f"[REDACTED {name}]"
                if pattern.groups >= 1:
                    # Preserve key-name prefix capture groups (aligned with SecretRedactor).
                    redacted = pattern.sub(rf"\g<1>{placeholder}", redacted)
                else:
                    redacted = pattern.sub(placeholder, redacted)

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
