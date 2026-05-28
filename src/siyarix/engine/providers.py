# SPDX-License-Identifier: AGPL-3.0-or-later

"""LLM provider configuration helpers for the execution engine."""

from __future__ import annotations

import logging
from typing import Any

from ..providers import registry as provider_registry

logger = logging.getLogger(__name__)

PREFERENCE_MAP: dict[str, list[str]] = {
    "gemini": [
        "gemini",
        "openai",
        "anthropic",
        "groq",
        "together",
        "ollama",
        "lmstudio",
        "cloud",
        "noop",
    ],
    "openai": [
        "openai",
        "gemini",
        "anthropic",
        "groq",
        "together",
        "ollama",
        "lmstudio",
        "cloud",
        "noop",
    ],
    "ollama": [
        "ollama",
        "lmstudio",
        "gemini",
        "openai",
        "anthropic",
        "groq",
        "together",
        "cloud",
        "noop",
    ],
    "cloud": [
        "cloud",
        "gemini",
        "openai",
        "anthropic",
        "groq",
        "together",
        "ollama",
        "lmstudio",
        "noop",
    ],
    "groq": [
        "groq",
        "openai",
        "gemini",
        "anthropic",
        "together",
        "ollama",
        "lmstudio",
        "cloud",
        "noop",
    ],
    "together": [
        "together",
        "groq",
        "openai",
        "gemini",
        "anthropic",
        "ollama",
        "lmstudio",
        "cloud",
        "noop",
    ],
    "lmstudio": [
        "lmstudio",
        "ollama",
        "gemini",
        "openai",
        "anthropic",
        "groq",
        "together",
        "cloud",
        "noop",
    ],
    "anthropic": [
        "anthropic",
        "openai",
        "gemini",
        "groq",
        "together",
        "ollama",
        "lmstudio",
        "cloud",
        "noop",
    ],
    "auto": [
        "gemini",
        "openai",
        "anthropic",
        "groq",
        "together",
        "ollama",
        "lmstudio",
        "cloud",
        "noop",
    ],
}


def setup_providers(
    planner: Any,
    config: dict[str, Any],
) -> None:
    """Configure model providers for a TaskPlanner based on available configuration."""
    preferred = str(config.get("model_provider", "auto")).strip().lower()
    order = PREFERENCE_MAP.get(preferred, PREFERENCE_MAP["auto"])

    for name in order:
        try:
            if name == "openai":
                api_key = config.get("openai_api_key", "")
                model = config.get("openai_model", "gpt-4o")
                prov = provider_registry.get(
                    "openai", api_key=api_key, model=model
                )
                available = bool(api_key)
            elif name == "gemini":
                api_key = config.get(
                    "gemini_api_key", ""
                ) or config.get("google_api_key", "")
                model = config.get("gemini_model", "gemini-1.5-pro")
                prov = provider_registry.get(
                    "gemini", api_key=api_key, model=model
                )
                available = bool(api_key)
            elif name == "ollama":
                url = config.get("ollama_url", "http://localhost:11434")
                model = config.get("ollama_model", "llama3.1")
                prov = provider_registry.get(
                    "ollama", base_url=url, model=model
                )
                available = True
            elif name == "cloud":
                server = config.get("server_url", "")
                key = config.get("api_key", "")
                prov = provider_registry.get(
                    "cloud", server_url=server, api_key=key
                )
                available = bool(server and key)
            elif name == "groq":
                api_key = config.get("groq_api_key", "")
                model = config.get("groq_model", "llama3-70b-8192")
                prov = provider_registry.get(
                    "groq", api_key=api_key, model=model
                )
                available = bool(api_key)
            elif name == "together":
                api_key = config.get("together_api_key", "")
                model = config.get(
                    "together_model",
                    "mistralai/Mixtral-8x7B-Instruct-v0.1",
                )
                prov = provider_registry.get(
                    "together", api_key=api_key, model=model
                )
                available = bool(api_key)
            elif name == "lmstudio":
                url = config.get("lmstudio_url", "http://localhost:1234")
                model = config.get("lmstudio_model", "")
                prov = provider_registry.get(
                    "lmstudio", base_url=url, model=model
                )
                available = True
            elif name == "anthropic":
                api_key = config.get("anthropic_api_key", "")
                model = config.get(
                    "anthropic_model", "claude-3-opus-20240229"
                )
                prov = provider_registry.get(
                    "anthropic", api_key=api_key, model=model
                )
                available = bool(api_key)
            else:
                prov = provider_registry.get("noop")
                available = True

            if not available:
                continue

            try:
                setattr(prov, "available", available)
            except Exception as exc:
                logger.debug("Failed to set availability on %s: %s", name, exc)

            planner.add_provider(prov)
        except Exception:
            logger.debug(
                "Failed to instantiate provider adapter: %s",
                name,
                exc_info=True,
            )
