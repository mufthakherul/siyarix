"""Provider abstraction and registry for AI backends.

Provides a unified interface for all AI model providers with:
- Provider protocol with async plan/chat/validate/close methods
- ProviderRegistry with preference ordering
- Built-in NoopProvider for offline/testing
- Support for OpenAI, Gemini, Ollama, and Cloud providers
- Automatic fallback chain configuration
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class Provider:
    """Common provider interface used by planner and engine.

    All model providers should implement this protocol.
    """

    available: bool = False

    async def plan(self, prompt: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    async def validate(self) -> bool:
        raise NotImplementedError

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int = 1024,
    ) -> dict[str, Any]:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


class NoopProvider(Provider):
    """No-op provider for offline/testing scenarios."""

    def __init__(self, *, response: str | None = None) -> None:
        self.available = True
        self.response = response
        self._name = "noop"

    async def plan(self, prompt: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        await asyncio.sleep(0)
        if self.response is None:
            return {}
        return {"plan": [f"noop: {prompt}"], "context": context or {}}

    async def validate(self) -> bool:
        return True

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int = 1024,
    ) -> dict[str, Any]:
        last = None
        for m in messages:
            last = m
        return {"reply": self.response or "(noop)", "last_message": last}

    async def close(self) -> None:
        return None


class ProviderRegistry:
    """Registry for provider factories and/or instances.

    Supports both class-based (factory) and instance-based registration.
    Providers can be queried by name, ordered by preference, and filtered
    by availability.
    """

    def __init__(self) -> None:
        self._providers: dict[str, Any] = {}
        self._ordered: list[tuple[str, Provider]] = []

    def register(self, name: str, provider: Any) -> None:
        if name in self._providers:
            logger.warning("Overwriting provider registration for %s", name)
        self._providers[name] = provider
        if not isinstance(provider, type):
            self._ordered.append((name, provider))

    def get(self, name: str, **kwargs: Any) -> Provider:
        provider = self._providers.get(name)
        if provider is None:
            raise KeyError(f"Unknown provider: {name}")
        if isinstance(provider, type):
            return provider(**kwargs)
        return provider

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())

    def get_list(self) -> list[Provider]:
        return [p for _, p in self._ordered]

    def available(self) -> list[Provider]:
        return [p for _, p in self._ordered if getattr(p, "available", False)]

    def ordered_by_preference(self, preferred: list[str] | None = None) -> list[Provider]:
        if not preferred:
            return self.get_list()
        preferred_lower = [p.lower() for p in preferred]
        ordered: list[Provider] = []
        others: list[Provider] = []
        for key, prov in self._ordered:
            if key.lower() in preferred_lower:
                ordered.append(prov)
            else:
                others.append(prov)
        ordered.extend(others)
        return ordered

    def clear(self) -> None:
        self._providers.clear()
        self._ordered.clear()


registry = ProviderRegistry()
registry.register("noop", NoopProvider)

__all__ = ["Provider", "ProviderRegistry", "NoopProvider", "registry"]
