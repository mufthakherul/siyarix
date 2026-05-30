# SPDX-License-Identifier: AGPL-3.0-or-later

"""Provider abstraction and registry for AI backends.

Provides a unified interface for all AI model providers with:
- Provider protocol with async plan/chat/validate/close methods
- ProviderRegistry with preference ordering
- Built-in NoopProvider for offline/testing
- Adapter classes wrapping planner models into the Provider ABC
- Automatic fallback chain configuration
- Circuit breaker per provider for graceful failure handling
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Circuit Breaker — lightweight implementation for provider failure handling
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Simple circuit breaker for model providers.

    States:
      CLOSED  → requests pass through (normal)
      OPEN    → requests short-circuited (provider failing)
      HALF    → single test request allowed after reset_timeout
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = 3,
        reset_timeout: float = 60.0,
        name: str = "unknown",
    ) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.name = name
        self._state = self.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0

    @property
    def state(self) -> str:
        if self._state == self.OPEN:
            if time.monotonic() - self._last_failure_time >= self.reset_timeout:
                self._state = self.HALF_OPEN
        return self._state

    @property
    def is_available(self) -> bool:
        return self.state != self.OPEN

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = self.CLOSED

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self.failure_threshold:
            self._state = self.OPEN
            logger.warning(
                "Circuit breaker OPEN for %s after %d failures",
                self.name,
                self._failure_count,
            )

    def reset(self) -> None:
        self._state = self.CLOSED
        self._failure_count = 0


class Provider(ABC):
    """Common provider interface used by planner and engine.

    All model providers should implement this protocol.
    """

    available: bool = False

    @abstractmethod
    async def plan(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def validate(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int = 1024,
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def close(self) -> None:
        raise NotImplementedError


class NoopProvider(Provider):
    """No-op provider for offline/testing scenarios."""

    def __init__(self, *, response: str | None = None) -> None:
        self.available = True
        self.response = response
        self._name = "noop"

    async def plan(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
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
        self._circuit_breakers: dict[str, CircuitBreaker] = {}

    def register(self, name: str, provider: Any) -> None:
        if name in self._providers:
            logger.warning("Overwriting provider registration for %s", name)
        self._providers[name] = provider
        if not isinstance(provider, type):
            self._ordered.append((name, provider))
            self._circuit_breakers[name] = CircuitBreaker(
                failure_threshold=3, reset_timeout=60.0, name=name
            )

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
        result: list[Provider] = []
        for name, p in self._ordered:
            if not getattr(p, "available", False):
                continue
            cb = self._circuit_breakers.get(name)
            if cb is not None and not cb.is_available:
                logger.debug(
                    "Circuit breaker OPEN for %s — skipping in available()", name
                )
                continue
            result.append(p)
        return result

    def ordered_by_preference(
        self, preferred: list[str] | None = None
    ) -> list[Provider]:
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

    def record_failure(self, name: str) -> None:
        """Record a failure for the given provider name's circuit breaker."""
        cb = self._circuit_breakers.get(name)
        if cb is not None:
            cb.record_failure()

    def record_success(self, name: str) -> None:
        """Record a success for the given provider name's circuit breaker."""
        cb = self._circuit_breakers.get(name)
        if cb is not None:
            cb.record_success()

    def clear(self) -> None:
        self._providers.clear()
        self._ordered.clear()
        self._circuit_breakers.clear()


registry = ProviderRegistry()
registry.register("noop", NoopProvider)


# ---------------------------------------------------------------------------
# Adapter classes — wrap planner model classes into the Provider ABC
# ---------------------------------------------------------------------------

class _PlannerModelLazy:
    """Lazy import of planner models to avoid circular imports at module level."""

    _models: dict[str, type] | None = None

    @classmethod
    def _ensure(cls) -> dict[str, type]:
        if cls._models is None:
            from . import planner as _p
            cls._models = {
                "OpenAIModel": _p.OpenAIModel,
                "GeminiModel": _p.GeminiModel,
                "OllamaModel": _p.OllamaModel,
                "CloudModel": _p.CloudModel,
                "GroqModel": _p.GroqModel,
                "TogetherModel": _p.TogetherModel,
                "LMStudioModel": _p.LMStudioModel,
                "CustomModel": _p.CustomModel,
            }
        return cls._models

    @classmethod
    def get(cls, name: str) -> type:
        return cls._ensure()[name]


class OpenAIAdapter(Provider):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o") -> None:
        model_cls = _PlannerModelLazy.get("OpenAIModel")
        self._impl: Any = model_cls(api_key=api_key, model=model)

    async def validate(self) -> bool:
        return bool(getattr(self._impl, "available", False))

    async def plan(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._impl.plan(prompt, context or {})

    async def chat(
        self, messages: list[dict[str, Any]], *, max_tokens: int = 1024
    ) -> dict[str, Any]:
        joined = "\n".join(m.get("content", "") for m in messages)
        return await self._impl.plan(joined, {})

    async def close(self) -> None:
        return None


class GeminiAdapter(OpenAIAdapter):
    def __init__(
        self, api_key: str | None = None, model: str = "gemini-1.5-pro"
    ) -> None:
        model_cls = _PlannerModelLazy.get("GeminiModel")
        self._impl = model_cls(api_key=api_key, model=model)


class OllamaAdapter(OpenAIAdapter):
    def __init__(
        self, base_url: str = "http://localhost:11434", model: str = "llama3.1"
    ) -> None:
        model_cls = _PlannerModelLazy.get("OllamaModel")
        self._impl = model_cls(base_url=base_url, model=model)


class CloudAdapter(OpenAIAdapter):
    def __init__(self, server_url: str = "", api_key: str = "") -> None:
        model_cls = _PlannerModelLazy.get("CloudModel")
        self._impl = model_cls(server_url=server_url, api_key=api_key)


class GroqAdapter(OpenAIAdapter):
    def __init__(
        self, api_key: str | None = None, model: str = "llama3-70b-8192"
    ) -> None:
        model_cls = _PlannerModelLazy.get("GroqModel")
        self._impl = model_cls(api_key=api_key, model=model)


class TogetherAdapter(OpenAIAdapter):
    def __init__(
        self,
        api_key: str | None = None,
        model: str = "mistralai/Mixtral-8x7B-Instruct-v0.1",
    ) -> None:
        model_cls = _PlannerModelLazy.get("TogetherModel")
        self._impl = model_cls(api_key=api_key, model=model)


class LMStudioAdapter(OpenAIAdapter):
    def __init__(
        self, base_url: str = "http://localhost:1234", model: str = ""
    ) -> None:
        model_cls = _PlannerModelLazy.get("LMStudioModel")
        self._impl = model_cls(base_url=base_url, model=model)


class CustomAdapter(OpenAIAdapter):
    def __init__(
        self, server_url: str = "", api_key: str = "", model: str = ""
    ) -> None:
        model_cls = _PlannerModelLazy.get("CustomModel")
        self._impl = model_cls(server_url=server_url, api_key=api_key, model=model)


class AnthropicAdapter(Provider):
    """Adapter for Anthropic Claude models."""

    def __init__(
        self, api_key: str | None = None, model: str = "claude-3-opus-20240229"
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model
        self.available = bool(self._api_key)

    async def validate(self) -> bool:
        return self.available

    async def plan(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        from .planner import _build_system_prompt

        if not self.available:
            return {}
        try:
            import anthropic
        except ImportError:
            return {}
        system_prompt = _build_system_prompt(context or {})
        try:
            client = anthropic.AsyncAnthropic(api_key=self._api_key)
            response = await client.messages.create(
                model=self._model,
                max_tokens=2048,
                temperature=0.1,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text if response.content else "{}"
            return json.loads(content)
        except Exception as exc:
            logger.warning("Anthropic planning failed: %s", exc)
            return {}

    async def chat(
        self, messages: list[dict[str, Any]], *, max_tokens: int = 1024
    ) -> dict[str, Any]:
        if not self.available:
            return {}
        try:
            import anthropic
        except ImportError:
            return {}
        try:
            client = anthropic.AsyncAnthropic(api_key=self._api_key)
            response = await client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                messages=[
                    {"role": m.get("role", "user"), "content": m.get("content", "")}
                    for m in messages
                ],
            )
            return {"reply": response.content[0].text if response.content else ""}
        except Exception as exc:
            logger.warning("Anthropic chat failed: %s", exc)
            return {}

    async def close(self) -> None:
        return None


class OpenCodeAdapter(OpenAIAdapter):
    """Adapter for OpenCode API (OpenAI-compatible)."""

    BASE_URL = "https://api.opencode.ai/v1"
    DEFAULT_MODEL = "deepseek-v4-flash-free"

    def __init__(
        self, api_key: str | None = None, model: str = DEFAULT_MODEL
    ) -> None:
        model_cls = _PlannerModelLazy.get("OpenAIModel")
        self._impl = model_cls(api_key=api_key, model=model, base_url=self.BASE_URL)


# Register adapter classes in the registry
registry.register("openai", OpenAIAdapter)
registry.register("gemini", GeminiAdapter)
registry.register("ollama", OllamaAdapter)
registry.register("cloud", CloudAdapter)
registry.register("groq", GroqAdapter)
registry.register("together", TogetherAdapter)
registry.register("lmstudio", LMStudioAdapter)
registry.register("custom", CustomAdapter)
registry.register("anthropic", AnthropicAdapter)
registry.register("opencode", OpenCodeAdapter)

__all__ = [
    "Provider", "ProviderRegistry", "NoopProvider", "CircuitBreaker", "registry",
    "OpenAIAdapter", "GeminiAdapter", "OllamaAdapter", "CloudAdapter",
    "GroqAdapter", "TogetherAdapter", "LMStudioAdapter", "CustomAdapter",
    "AnthropicAdapter", "OpenCodeAdapter",
]
