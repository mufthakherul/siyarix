from __future__ import annotations

from typing import Any

from . import LlmCallable, StreamWrapper, register_wrapper


def wrap_openrouter(
    call_fn: LlmCallable, provider: str, model: str, options: dict[str, Any]
) -> LlmCallable:
    """Apply OpenRouter-specific headers and routing options.

    OpenClaw pattern: stream-wrappers/proxy.ts
    """
    if provider != "openrouter":
        return call_fn

    allow_fallbacks = options.pop("allow_fallbacks", True)
    if not allow_fallbacks:
        options.setdefault("extra_headers", {})["X-Title"] = "Siyarix"

    order = options.pop("provider_order", None)
    if order:
        options.setdefault("extra_headers", {})["X-OpenRouter-Provider-Order"] = ",".join(order)

    return call_fn


register_wrapper("openrouter", wrap_openrouter)
