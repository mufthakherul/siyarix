"""Provider abstraction and registry for AI backends."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Iterable, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class Provider(Protocol):
    """Common provider interface used by planner and engine."""

    available: bool

    async def plan(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ...

    async def validate(self) -> bool:
        ...

    async def chat(
        self,
        messages: Iterable[Dict[str, Any]],
        *,
        max_tokens: int = 1024,
    ) -> Dict[str, Any]:
        ...

    async def close(self) -> None:
        ...


class NoopProvider:
    """No-op provider for offline/testing scenarios."""

    def __init__(self, *, response: str | None = None) -> None:
        self.available = True
        self.response = response

    async def plan(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        await asyncio.sleep(0)
        if self.response is None:
            return {}
        return {"plan": [f"noop: {prompt}"], "context": context or {}}

    async def validate(self) -> bool:
        return True

    async def chat(
        self,
        messages: Iterable[Dict[str, Any]],
        *,
        max_tokens: int = 1024,  # noqa: ARG002
    ) -> Dict[str, Any]:
        last = None
        for m in messages:
            last = m
        return {"reply": self.response or "(noop)", "last_message": last}

    async def close(self) -> None:
        return None


class ProviderRegistry:
    """Registry for provider factories and/or instances."""

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

    def list_providers(self) -> List[str]:
        return list(self._providers.keys())

    def list(self) -> List[Provider]:
        return [p for _, p in self._ordered]

    def available(self) -> List[Provider]:
        return [p for _, p in self._ordered if getattr(p, "available", False)]

    def ordered_by_preference(self, preferred: List[str] | None = None) -> List[Provider]:
        if not preferred:
            return self.list()
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


registry = ProviderRegistry()
registry.register("noop", NoopProvider)

__all__ = ["Provider", "ProviderRegistry", "NoopProvider", "registry"]
