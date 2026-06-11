from __future__ import annotations

from typing import Any

from . import LlmCallable, StreamWrapper, register_wrapper


def wrap_cache_control(
    call_fn: LlmCallable, provider: str, model: str, options: dict[str, Any]
) -> LlmCallable:
    """Apply Anthropic-style ephemeral cache control markers.

    OpenClaw pattern: stream-wrappers/anthropic-cache-control-payload.ts
    """
    use_cache = options.pop("use_cache", False) or options.get("cache_control") == "ephemeral"
    if not use_cache or provider != "anthropic":
        return call_fn

    options["cache_control"] = {"type": "ephemeral"}

    return call_fn


register_wrapper("anthropic", wrap_cache_control)
