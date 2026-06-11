"""Unified OpenAI-compatible adapter — handles all OpenAI API-compatible providers.

OpenClaw pattern: a single `openai-completions.ts` shared by ~15 providers.
Provider-specific behavior is auto-detected via `detect_compat()` reading the
provider name and base URL, emitting compat flags (thinking format, max tokens
field, role support, etc.).

Usage:
    client = make_client(provider, api_key, base_url)
    result = await openai_complete(client, model, system, user, history)
    async for token in openai_stream(client, model, system, user, history):
        ...
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator

# ── Compat flags dataclass ─────────────────────────────────────────────


@dataclass
class OpenAICompat:
    """Auto-detected compatibility flags for an OpenAI-compatible provider.

    Mirrors OpenClaw's ``OpenAICompletionsCompat`` interface.
    """

    # ── provider identity ──
    provider: str = ""
    base_url: str = ""

    # ── thinking / reasoning ──
    thinking_format: str = "openai"
    """How to pass reasoning instructions: "openai" | "deepseek" | "zai" | "together" | "openrouter" """

    supports_reasoning_effort: bool = True
    """Whether the provider accepts 'reasoning_effort' parameter"""

    requires_reasoning_content_on_assistant: bool = False
    """Whether replayed assistant messages must include 'reasoning_content: ""'"""

    # ── message roles ──
    supports_developer_role: bool = True
    """Whether 'developer' role is accepted (vs 'system') for reasoning models"""

    supports_store: bool = True
    """Whether 'store: false' should be sent"""

    requires_tool_result_name: bool = False
    """Whether tool result messages need a 'name' field"""

    requires_assistant_after_tool_result: bool = False
    """Whether to insert a synthetic assistant message after tool results before user"""

    requires_thinking_as_text: bool = False
    """Whether thinking blocks should be converted to plain text"""

    # ── parameters ──
    max_tokens_field: str = "max_completion_tokens"
    """"max_tokens" or "max_completion_tokens" """

    supports_strict_mode: bool = True
    """Whether 'strict: false' can be sent in tool definitions"""

    supports_usage_in_streaming: bool = True
    """Whether 'stream_options: {include_usage: true}' is supported"""

    cache_control_format: str | None = None
    """Cache control format: None | "anthropic" """

    zai_tool_stream: bool = False
    """Whether to use Z.AI's 'tool_stream: true' """

    # ── session ──
    send_session_affinity_headers: bool = False
    """Whether to send session affinity headers"""

    supports_prompt_cache_key: bool = False
    """Whether 'prompt_cache_key' parameter is supported"""

    supports_long_cache_retention: bool = True
    """Whether longer cache TTL is supported"""


# ── Provider config (dict-based, no separate db needed) ────────────────
# Maps provider name -> (base_url, default_model, api_key_env)
# This is the single source of truth for all OpenAI-compatible providers.

PROVIDER_CONFIG: dict[str, tuple[str, str, str]] = {
    "openai": ("", "gpt-5.4", "OPENAI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "openai/gpt-5.4", "OPENROUTER_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-3.5-flash", "GEMINI_API_KEY"),
    "deepseek": ("https://api.deepseek.com", "deepseek-v4-flash", "DEEPSEEK_API_KEY"),
    "xai": ("https://api.x.ai", "grok-4.3", "XAI_API_KEY"),
    "perplexity": ("https://api.perplexity.ai", "sonar", "PERPLEXITY_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1", "llama-4-scout-17b-16e-instruct", "GROQ_API_KEY"),
    "together": ("https://api.together.xyz/v1", "meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8", "TOGETHER_API_KEY"),
    "cerebras": ("https://api.cerebras.ai/v1", "zai-glm-4.7", "CEREBRAS_API_KEY"),
    "fireworks": ("https://api.fireworks.ai/inference/v1", "accounts/fireworks/routers/kimi-k2p5-turbo", "FIREWORKS_API_KEY"),
    "zai": ("https://api.z.ai/api/paas/v4", "glm-5", "ZAI_API_KEY"),
    "minimax": ("https://api.minimax.io/v1", "MiniMax-M3", "MINIMAX_API_KEY"),
    "moonshot": ("https://api.moonshot.ai/v1", "kimi-k2.6", "MOONSHOT_API_KEY"),
    "nvidia": ("https://integrate.api.nvidia.com/v1", "nvidia/nemotron-3-super-120b-a12b", "NVIDIA_API_KEY"),
    "opencode-go": ("https://opencode.ai/zen/go/v1", "deepseek-v4-flash", "OPENCODE_GO_API_KEY"),
    "huggingface": ("https://api-inference.huggingface.co/v1", "", "HUGGINGFACE_API_KEY"),
    "azure": ("", "gpt-5.4", "AZURE_OPENAI_API_KEY"),
    "llamacpp": ("http://localhost:8080", "", ""),
    "vllm": ("http://localhost:8000", "", ""),
    "localai": ("http://localhost:8080", "", ""),
}


# ── Config key mappings (used by chat __init__) ──────────────────────

MODEL_KEYS: dict[str, str] = {
    "openai": "openai_model",
    "openrouter": "openrouter_model",
    "gemini": "gemini_model",
    "deepseek": "deepseek_model",
    "xai": "xai_model",
    "perplexity": "perplexity_model",
    "groq": "groq_model",
    "together": "together_model",
    "azure": "azure_model",
    "cerebras": "cerebras_model",
    "fireworks": "fireworks_model",
    "zai": "zai_model",
    "minimax": "minimax_model",
    "moonshot": "moonshot_model",
    "nvidia": "nvidia_model",
    "opencode-go": "opencode_go_model",
    "huggingface": "huggingface_model",
    "llamacpp": "llamacpp_model",
    "vllm": "vllm_model",
    "localai": "localai_model",
}


# ── detect_compat(): auto-detect provider flags ────────────────────────
# Mirrors OpenClaw's detectCompat() in openai-completions.ts


def detect_compat(provider: str, base_url: str) -> OpenAICompat:
    """Auto-detect compatibility flags from provider name and base URL.

    Provider name takes precedence over URL-based detection.
    """
    merged_url = (PROVIDER_CONFIG.get(provider, ("", "", ""))[0]) or base_url
    effective_base = base_url or merged_url

    # ── provider identification (name + URL patterns) ──
    is_zai = provider == "zai" or "api.z.ai" in effective_base
    is_together = provider == "together" or "api.together.xyz" in effective_base or "api.together.ai" in effective_base
    is_moonshot = provider == "moonshot" or "api.moonshot." in effective_base
    is_grok = provider == "xai" or "api.x.ai" in effective_base
    is_deepseek = provider == "deepseek" or "deepseek.com" in effective_base
    is_cerebras = provider == "cerebras" or "cerebras.ai" in effective_base
    is_openrouter = provider == "openrouter" or "openrouter.ai" in effective_base
    is_perplexity = provider == "perplexity" or "perplexity.ai" in effective_base
    is_cloudflare = "gateway.ai.cloudflare.com" in effective_base

    is_non_standard = any([
        is_cerebras, is_grok, is_together, is_zai, is_moonshot,
        is_deepseek, provider == "opencode-go", "opencode.ai" in effective_base,
        is_cloudflare, "chutes.ai" in effective_base,
    ])

    use_max_tokens = any([
        is_moonshot, is_together, is_cloudflare, "chutes.ai" in effective_base,
    ])

    # ── thinking format detection ──
    if is_deepseek:
        thinking_format = "deepseek"
    elif is_zai:
        thinking_format = "zai"
    elif is_together:
        thinking_format = "together"
    elif is_openrouter:
        thinking_format = "openrouter"
    else:
        thinking_format = "openai"

    # ── reasoning effort support ──
    supports_reasoning = not (is_grok or is_zai or is_moonshot or is_together or is_cloudflare)

    supports_developer = not is_non_standard
    supports_store = not is_non_standard

    requires_reasoning_content = is_deepseek

    ccf = "anthropic" if is_openrouter else None

    return OpenAICompat(
        provider=provider,
        base_url=effective_base,
        # thinking
        thinking_format=thinking_format,
        supports_reasoning_effort=supports_reasoning,
        requires_reasoning_content_on_assistant=requires_reasoning_content,
        # roles
        supports_developer_role=supports_developer,
        supports_store=supports_store,
        requires_tool_result_name=False,
        requires_assistant_after_tool_result=False,
        requires_thinking_as_text=False,
        # params
        max_tokens_field="max_tokens" if use_max_tokens else "max_completion_tokens",
        supports_strict_mode=not (is_moonshot or is_together or is_cloudflare),
        supports_usage_in_streaming=True,
        cache_control_format=ccf,
        zai_tool_stream=is_zai,
        # session
        send_session_affinity_headers=False,
        supports_prompt_cache_key=False,
        supports_long_cache_retention=not (is_together or is_cloudflare),
    )


# ── Helper: resolve model from settings ────────────────────────────────
# Takes a settings-like object (dict or obj with .get()) and returns
# the resolved model ID for the given provider.

def resolve_model(
    provider: str,
    settings: Any,
    provider_manager: Any = None,
) -> str:
    """Resolve the model ID from settings for a given provider."""
    model_key = MODEL_KEYS.get(provider)
    default_model = PROVIDER_CONFIG.get(provider, ("", "", ""))[1]
    raw_model = ""
    if model_key and hasattr(settings, "get"):
        raw_model = settings.get(model_key) or default_model
    elif isinstance(settings, dict):
        raw_model = settings.get(model_key) or default_model
    else:
        raw_model = default_model
    if provider_manager and hasattr(provider_manager, "resolve_model_id"):
        return provider_manager.resolve_model_id(provider, raw_model)
    return raw_model or default_model or provider


# ── Helper: build messages list ───────────────────────────────────────

def build_messages(
    system_prompt: str,
    user_prompt: str,
    history: list[dict] | None = None,
    *,
    compat: OpenAICompat | None = None,
) -> list[dict[str, Any]]:
    """Build the messages list for an OpenAI-compatible API call.

    Supports system, developer (for reasoning models), user, and assistant roles.
    When *compat* is provided and its *supports_developer_role* flag is True,
    uses ``"developer"`` role instead of ``"system"`` for reasoning-optimised models.
    """
    messages: list[dict[str, Any]] = []
    if system_prompt:
        use_dev = compat is not None and compat.supports_developer_role
        role = "developer" if use_dev else "system"
        messages.append({"role": role, "content": system_prompt})
    if history:
        for msg in history:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                continue
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": user_prompt})
    return messages


# ── Client factory ─────────────────────────────────────────────────────

def make_client(
    provider: str,
    api_key: str,
    base_url: str | None = None,
    compat: OpenAICompat | None = None,
) -> Any:
    """Create an AsyncOpenAI client for the given provider.

    Uses the provider config to resolve base_url if not provided,
    and applies any provider-specific client customizations.
    """
    from openai import AsyncOpenAI

    resolved_base_url = base_url
    if not resolved_base_url or resolved_base_url.strip() == "":
        resolved_base_url = PROVIDER_CONFIG.get(provider, ("", "", ""))[0] or None

    if resolved_base_url:
        return AsyncOpenAI(api_key=api_key, base_url=resolved_base_url)
    return AsyncOpenAI(api_key=api_key)


# ── Unified streaming function ─────────────────────────────────────────
# Mirrors OpenClaw's openai-completions.ts streamOpenAICompletions()

async def openai_stream(
    client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    history: list[dict] | None = None,
    *,
    max_tokens: int = 2000,
    temperature: float = 0.3,
    compat: OpenAICompat | None = None,
) -> AsyncGenerator[str, None]:
    """Stream a response from any OpenAI-compatible provider.

    Yields content tokens as they arrive.
    """
    messages = build_messages(system_prompt, user_prompt, history, compat=compat)
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    response = await client.chat.completions.create(**kwargs)
    async for chunk in response:
        if chunk.choices and len(chunk.choices) > 0:
            delta = chunk.choices[0].delta
            if delta and delta.content:
                yield delta.content


# ── Unified completion function ────────────────────────────────────────

async def openai_complete(
    client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    history: list[dict] | None = None,
    *,
    max_tokens: int = 2000,
    temperature: float = 0.3,
    compat: OpenAICompat | None = None,
) -> dict[str, Any]:
    """Complete a chat request from any OpenAI-compatible provider.

    Returns dict with content, model, input_tokens, output_tokens.
    """
    messages = build_messages(system_prompt, user_prompt, history, compat=compat)
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    try:
        response = await client.chat.completions.create(**kwargs)
    except Exception as exc:
        msg = str(exc) or repr(exc)
        raise RuntimeError(f"API call failed (model={model}): {msg}") from exc

    choice = response.choices[0]
    usage = response.usage
    return {
        "content": choice.message.content or "",
        "model": response.model or model,
        "input_tokens": usage.prompt_tokens if usage else 0,
        "output_tokens": usage.completion_tokens if usage else 0,
    }


# ── High-level adapter (returns the async callable) ────────────────────
# Used by chat/__init__.py:_make_llm_call() to replace the duplicated
# if-else blocks.

def make_openai_adapter(
    provider: str,
    api_key: str,
    base_url: str | None = None,
    settings: Any = None,
    provider_manager: Any = None,
) -> Any:
    """Create an async callable for an OpenAI-compatible provider.

    Returns an async function with signature:
        (system, user, *, stream=False, history=None) -> dict | AsyncGenerator
    """
    client = make_client(provider, api_key, base_url)
    compat = detect_compat(provider, base_url or "")
    model = resolve_model(provider, settings, provider_manager)

    async def adapter(
        system_prompt: str,
        user_prompt: str,
        *,
        stream: bool = False,
        history: list[dict] | None = None,
    ) -> dict[str, Any]:
        if stream:
            return openai_stream(
                client, model, system_prompt, user_prompt,
                history=history, compat=compat,
            )
        return await openai_complete(
            client, model, system_prompt, user_prompt,
            history=history, compat=compat,
        )

    return adapter
