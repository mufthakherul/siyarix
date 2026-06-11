from __future__ import annotations

from typing import Any

from . import LlmCallable, StreamWrapper, register_wrapper


def wrap_service_tier(
    call_fn: LlmCallable, provider: str, model: str, options: dict[str, Any]
) -> LlmCallable:
    """Apply OpenAI service tier (auto/default/priority) based on model.

    OpenClaw pattern: stream-wrappers/openai.ts lines 370-372
    """
    fast_mode = options.pop("fast_mode", False) or options.get("service_tier") == "priority"
    if not fast_mode or provider not in ("openai", "azure"):
        return call_fn

    premium_models = {"gpt-5.5", "gpt-5.5-pro", "gpt-5.4", "gpt-5.4-pro"}
    is_premium = any(m in model for m in premium_models)
    if is_premium:
        options["service_tier"] = "priority"

    return call_fn


register_wrapper("openai", wrap_service_tier)
register_wrapper("azure", wrap_service_tier)
