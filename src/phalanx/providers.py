"""Provider abstractions and registry for model/LLM providers.

This module introduces a minimal Provider protocol, a NoopProvider
useful for testing/offline operation, and a ProviderRegistry to hold
ordered providers and preference selection.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class Provider(Protocol):
    """Protocol for LLM/model providers used by the planner."""

    available: bool

    async def plan(self, prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        ...


class NoopProvider:
    """A provider that does nothing: useful for offline testing or as fallback."""

    def __init__(self) -> None:
        self.available = True

    async def plan(self, prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0)
        logger.debug("NoopProvider.plan called (prompt length=%d)", len(prompt) if prompt else 0)
        return {}


class ProviderRegistry:
    """Holds providers and exposes ordered/filtered lists.

    Providers can be registered with an optional key (e.g., 'openai', 'gemini').
    """

    def __init__(self) -> None:
        self._providers: List[tuple[str, Provider]] = []

    def register(self, key: str, provider: Provider) -> None:
        self._providers.append((key, provider))

    def list(self) -> List[Provider]:
        return [p for _, p in self._providers]

    def available(self) -> List[Provider]:
        return [p for _, p in self._providers if getattr(p, "available", False)]

    def ordered_by_preference(self, preferred: List[str] | None = None) -> List[Provider]:
        if not preferred:
            return self.list()
        preferred_lower = [p.lower() for p in preferred]
        ordered: List[Provider] = []
        others: List[Provider] = []
        for key, prov in self._providers:
            if key.lower() in preferred_lower:
                ordered.append(prov)
            else:
                others.append(prov)
        ordered.extend(others)
        return ordered


__all__ = ["Provider", "NoopProvider", "ProviderRegistry"]
"""Provider abstraction and registry for AI backends.

Defines a small, testable interface for AI providers and a registry
to manage available provider implementations. Adapters for OpenAI,
Gemini, Ollama, etc. will implement this interface.
"""
from __future__ import annotations

import abc
import logging
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)


class Provider(abc.ABC):
    """Abstract provider interface.

    Implementations should be lightweight and thread-safe where possible.
    """

    @abc.abstractmethod
    async def validate(self) -> bool:
        """Async validate connectivity/credentials. Return True if provider is available."""

    @abc.abstractmethod
    async def plan(self, prompt: str, *, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return a structured plan for a given prompt.

        The return value should be JSON-serializable.
        """

    @abc.abstractmethod
    async def chat(self, messages: Iterable[Dict[str, Any]], *, max_tokens: int = 1024) -> Dict[str, Any]:
        """Send chat-style messages and return model response payload."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Clean up any persistent resources (connections, threads)."""


class ProviderRegistry:
    """Registry for provider factories.

    Stores provider classes (or callables) and can instantiate them on demand.
    """

    def __init__(self) -> None:
        self._providers: Dict[str, type[Provider]] = {}

    def register(self, name: str, cls: type[Provider]) -> None:
        if name in self._providers:
            logger.warning("Overwriting provider registration for %s", name)
        self._providers[name] = cls

    def get(self, name: str, **kwargs: Any) -> Provider:
        cls = self._providers.get(name)
        if cls is None:
            raise KeyError(f"Unknown provider: {name}")
        return cls(**kwargs)

    def list_providers(self) -> Iterable[str]:
        return list(self._providers.keys())


# Lightweight no-op provider for testing and offline scenarios
class NoopProvider(Provider):
    def __init__(self, *, response: str = "(noop)") -> None:
        self.response = response

    async def validate(self) -> bool:
        return True

    async def plan(self, prompt: str, *, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"plan": [f"noop: {prompt}"], "context": context or {}}

    async def chat(self, messages: Iterable[Dict[str, Any]], *, max_tokens: int = 1024) -> Dict[str, Any]:
        last = None
        for m in messages:
            last = m
        return {"reply": self.response, "last_message": last}

    async def close(self) -> None:
        return None


registry = ProviderRegistry()
registry.register("noop", NoopProvider)

__all__ = ["Provider", "ProviderRegistry", "NoopProvider", "registry"]
