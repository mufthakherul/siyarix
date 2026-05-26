"""Provider abstraction and registry for AI backends.

Provides a unified interface for all AI model providers with:
- Provider protocol with async plan/chat/validate/close methods
- ProviderRegistry with preference ordering
- Built-in NoopProvider for offline/testing
- Adapter classes wrapping planner models into the Provider ABC
- Automatic fallback chain configuration
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class Provider:
    """Common provider interface used by planner and engine.

    All model providers should implement this protocol.
    """

    available: bool = False

    async def plan(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
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

    def clear(self) -> None:
        self._providers.clear()
        self._ordered.clear()


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

    @property
    def available(self) -> bool:
        return bool(self._api_key)

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

__all__ = [
    "Provider", "ProviderRegistry", "NoopProvider", "registry",
    "OpenAIAdapter", "GeminiAdapter", "OllamaAdapter", "CloudAdapter",
    "GroqAdapter", "TogetherAdapter", "LMStudioAdapter", "CustomAdapter",
    "AnthropicAdapter",
]
