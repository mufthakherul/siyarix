from __future__ import annotations

from typing import Any

from . import LlmCallable, StreamWrapper, register_wrapper


def wrap_reasoning_effort(
    call_fn: LlmCallable, provider: str, model: str, options: dict[str, Any]
) -> LlmCallable:
    """Map thinking levels to provider-specific reasoning formats.

    OpenClaw pattern: reasoning-effort-utils.ts, stream-wrappers/openai.ts
    """

    thinking_level = options.pop("thinking_level", None) or options.get("reasoning_effort")

    if not thinking_level or thinking_level == "off":
        return call_fn

    effort_map: dict[str, str] = {
        "minimal": "low",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "xhigh": "high",
        "max": "high",
    }
    mapped = effort_map.get(thinking_level, "medium")

    provider_effort_map: dict[str, dict[str, Any]] = {
        "openai": {"reasoning_effort": mapped},
        "openrouter": {"reasoning_effort": mapped, "provider": {"order": ["OpenAI"]}},
        "deepseek": {},
        "xai": {},
        "gemini": {},
    }

    extra_kwargs = provider_effort_map.get(provider, {})
    if extra_kwargs:
        options.update(extra_kwargs)

    return call_fn


register_wrapper("*", wrap_reasoning_effort)
