# SPDX-License-Identifier: AGPL-3.0-or-later
"""API-key credential helpers shared by the CLI (extracted from the god-module)."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

PROVIDER_ENV_MAP: dict[str, str] = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY",
    "together": "TOGETHER_API_KEY",
}

_creds_store: Any = None


def get_creds() -> Any:
    """Lazy CredentialStore; also hydrates provider env vars from the store."""
    global _creds_store
    if _creds_store is None:
        try:
            from siyarix.credential_store import CredentialStore

            _creds_store = CredentialStore()
            for provider, env_var in PROVIDER_ENV_MAP.items():
                if not os.environ.get(env_var):
                    try:
                        key = _creds_store.retrieve(provider, "api_key")
                        if key:
                            os.environ[env_var] = key
                    except Exception:
                        logger.debug("API key not available for provider %s", provider)
        except Exception:
            logger.debug("CredentialStore not available")
            _creds_store = False
    return _creds_store if _creds_store else None


def resolve_key(provider: str) -> str:
    """Resolve API key from credential store → env."""
    from siyarix.providers import resolve_api_key

    env_var = PROVIDER_ENV_MAP.get(provider, f"{provider.upper()}_API_KEY")
    if not os.environ.get(env_var):
        cs = get_creds()
        if cs:
            try:
                key = cs.retrieve(provider, "api_key")
                if key:
                    os.environ[env_var] = key
            except Exception:
                logger.debug("API key not in credential store for provider %s", provider)
    val = resolve_api_key(provider, env_var) or ""
    if val:
        os.environ[env_var] = val
    return val


def store_key(provider: str, key: str) -> None:
    """Store API key in CredentialStore and environment."""
    env_var = PROVIDER_ENV_MAP.get(provider, f"{provider.upper()}_API_KEY")
    os.environ[env_var] = key
    cs = get_creds()
    if cs:
        try:
            cs.store(provider, key, "api_key")
        except Exception:
            logger.warning("Failed to store API key for provider %s", provider, exc_info=True)


def delete_key(provider: str) -> None:
    """Delete API key from CredentialStore and environment."""
    env_var = PROVIDER_ENV_MAP.get(provider, f"{provider.upper()}_API_KEY")
    os.environ.pop(env_var, None)
    cs = get_creds()
    if cs:
        try:
            cs.delete(provider, "api_key")
        except Exception:
            logger.warning("Failed to delete API key for provider %s", provider, exc_info=True)
