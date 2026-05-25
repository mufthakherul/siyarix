"""Adapter layer to wrap planner model classes into the Provider ABC from providers.py.

This ensures a single provider interface for registry and engine usage.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Iterable, Optional

from . import planner as _planner
from .providers import Provider, registry

logger = logging.getLogger(__name__)


class OpenAIAdapter(Provider):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o") -> None:
        self._impl: Any = _planner.OpenAIModel(api_key=api_key, model=model)

    async def validate(self) -> bool:
        return bool(getattr(self._impl, "available", False))

    async def plan(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._impl.plan(prompt, context or {})

    async def chat(
        self, messages: Iterable[Dict[str, Any]], *, max_tokens: int = 1024
    ) -> Dict[str, Any]:
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



class GroqAdapter(OpenAIAdapter):
    def __init__(self, api_key: str | None = None, model: str = "llama3-70b-8192") -> None:
        self._impl = _planner.GroqModel(api_key=api_key, model=model)


class TogetherAdapter(OpenAIAdapter):
    def __init__(
        self, api_key: str | None = None, model: str = "mistralai/Mixtral-8x7B-Instruct-v0.1"
    ) -> None:
        self._impl = _planner.TogetherModel(api_key=api_key, model=model)


class LMStudioAdapter(OpenAIAdapter):
    def __init__(self, base_url: str = "http://localhost:1234", model: str = "") -> None:
        self._impl = _planner.LMStudioModel(base_url=base_url, model=model)


class CustomAdapter(OpenAIAdapter):
    def __init__(self, server_url: str = "", api_key: str = "", model: str = "") -> None:
        self._impl = _planner.CustomModel(server_url=server_url, api_key=api_key, model=model)


class AnthropicAdapter(Provider):
    """Adapter for Anthropic Claude models."""

    def __init__(self, api_key: str | None = None, model: str = "claude-3-opus-20240229") -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def validate(self) -> bool:
        return self.available

    async def plan(self, prompt: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
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
        self, messages: Iterable[Dict[str, Any]], *, max_tokens: int = 1024
    ) -> Dict[str, Any]:
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
                messages=[{"role": m.get("role", "user"), "content": m.get("content", "")} for m in messages],
            )
            return {"reply": response.content[0].text if response.content else ""}
        except Exception as exc:
            logger.warning("Anthropic chat failed: %s", exc)
            return {}

    async def close(self) -> None:
        return None


# Register adapters in the provider registry for convenience
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
    "OpenAIAdapter",
    "GeminiAdapter",
    "OllamaAdapter",
    "CloudAdapter",
    "GroqAdapter",
    "TogetherAdapter",
    "LMStudioAdapter",
    "CustomAdapter",
    "AnthropicAdapter",
]
