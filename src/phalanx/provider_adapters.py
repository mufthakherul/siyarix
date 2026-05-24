"""Adapter layer to wrap planner model classes into the Provider ABC from providers.py.

This ensures a single provider interface for registry and engine usage.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from . import planner as _planner
from .providers import Provider, registry


class OpenAIAdapter(Provider):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o") -> None:
        self._impl = _planner.OpenAIModel(api_key=api_key, model=model)

    async def validate(self) -> bool:
        return bool(getattr(self._impl, "available", False))

    async def plan(self, prompt: str, *, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._impl.plan(prompt, context or {})

    async def chat(self, messages: Iterable[Dict[str, Any]], *, max_tokens: int = 1024) -> Dict[str, Any]:
        # Planner OpenAIModel does not implement chat; provide minimal bridge
        # by concatenating messages for a plan-like response
        joined = "\n".join(m.get("content", "") for m in messages)
        return await self._impl.plan(joined, {})

    async def close(self) -> None:
        return None


class GeminiAdapter(OpenAIAdapter):
    def __init__(self, api_key: str | None = None, model: str = "gemini-1.5-pro") -> None:
        self._impl = _planner.GeminiModel(api_key=api_key, model=model)


class OllamaAdapter(OpenAIAdapter):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1") -> None:
        self._impl = _planner.OllamaModel(base_url=base_url, model=model)


class CloudAdapter(OpenAIAdapter):
    def __init__(self, server_url: str = "", api_key: str = "") -> None:
        self._impl = _planner.CloudModel(server_url=server_url, api_key=api_key)


# Register adapters in the provider registry for convenience
registry.register("openai", OpenAIAdapter)
registry.register("gemini", GeminiAdapter)
registry.register("ollama", OllamaAdapter)
registry.register("cloud", CloudAdapter)

__all__ = ["OpenAIAdapter", "GeminiAdapter", "OllamaAdapter", "CloudAdapter"]
