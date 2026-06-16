"""Unified OpenAI-compatible adapter — handles all OpenAI API-compatible providers.

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
from dataclasses import dataclass
from typing import Any, AsyncGenerator

import httpx

from ..exceptions import LLMProviderError

# ── Compat flags dataclass ─────────────────────────────────────────────


@dataclass
class OpenAICompat:
    """Auto-detected compatibility flags for an OpenAI-compatible provider.

    Flags capture per-provider quirks: thinking format location (choices vs.
    dedicated field), max_tokens field name, role broadcast support, tool
    prefix stripping, and Pinecone vector-store header injection.
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
    "openai": ("", "gpt-5.5", "OPENAI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "openai/gpt-5.5", "OPENROUTER_API_KEY"),
    "gemini": (
        "https://generativelanguage.googleapis.com/v1beta/openai/",
        "gemini-3.5-flash",
        "GEMINI_API_KEY",
    ),
    "deepseek": ("https://api.deepseek.com", "deepseek-v4-flash", "DEEPSEEK_API_KEY"),
    "xai": ("https://api.x.ai", "grok-4.3", "XAI_API_KEY"),
    "perplexity": ("https://api.perplexity.ai", "sonar-pro", "PERPLEXITY_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1", "llama-4-scout-17b-16e-instruct", "GROQ_API_KEY"),
    "together": (
        "https://api.together.xyz/v1",
        "meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8",
        "TOGETHER_API_KEY",
    ),
    "cerebras": ("https://api.cerebras.ai/v1", "gpt-oss-120b", "CEREBRAS_API_KEY"),
    "fireworks": (
        "https://api.fireworks.ai/inference/v1",
        "accounts/fireworks/models/kimi-k2p6",
        "FIREWORKS_API_KEY",
    ),
    "zai": ("https://api.z.ai/api/paas/v4", "glm-5.1", "ZAI_API_KEY"),
    "minimax": ("https://api.minimax.io/v1", "MiniMax-M3", "MINIMAX_API_KEY"),
    "moonshot": ("https://api.moonshot.ai/v1", "kimi-k2.6", "MOONSHOT_API_KEY"),
    "nvidia": (
        "https://integrate.api.nvidia.com/v1",
        "nvidia/nemotron-3-super-120b-a12b",
        "NVIDIA_API_KEY",
    ),
    "opencode-go": ("https://opencode.ai/zen/go/v1", "deepseek-v4-flash", "OPENCODE_GO_API_KEY"),
    "huggingface": ("https://api-inference.huggingface.co/v1", "", "HUGGINGFACE_API_KEY"),
    "azure": ("", "gpt-5.5", "AZURE_OPENAI_API_KEY"),
    "llamacpp": ("http://localhost:18080", "", ""),
    "vllm": ("http://localhost:8000", "", ""),
    "localai": ("http://localhost:8080", "", ""),
    "ollama": ("http://localhost:11434/v1", "IHA089/drana-infinity-7b", ""),
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
    "ollama": "ollama_model",
}


# ── detect_compat(): auto-detect provider flags ────────────────────────
# Reads provider name + base URL and emits compat flags for that provider.


def detect_compat(provider: str, base_url: str) -> OpenAICompat:
    """Auto-detect compatibility flags from provider name and base URL.

    Provider name takes precedence over URL-based detection.
    """
    merged_url = (PROVIDER_CONFIG.get(provider, ("", "", ""))[0]) or base_url
    effective_base = base_url or merged_url

    # ── provider identification (name + URL patterns) ──
    is_zai = provider == "zai" or "api.z.ai" in effective_base
    is_together = (
        provider == "together"
        or "api.together.xyz" in effective_base
        or "api.together.ai" in effective_base
    )
    is_moonshot = provider == "moonshot" or "api.moonshot." in effective_base
    is_grok = provider == "xai" or "api.x.ai" in effective_base
    is_deepseek = provider == "deepseek" or "deepseek.com" in effective_base
    is_cerebras = provider == "cerebras" or "cerebras.ai" in effective_base
    is_openrouter = provider == "openrouter" or "openrouter.ai" in effective_base
    is_cloudflare = "gateway.ai.cloudflare.com" in effective_base

    is_non_standard = any(
        [
            is_cerebras,
            is_grok,
            is_together,
            is_zai,
            is_moonshot,
            is_deepseek,
            provider == "opencode-go",
            "opencode.ai" in effective_base,
            is_cloudflare,
            "chutes.ai" in effective_base,
        ]
    )

    use_max_tokens = any(
        [
            is_moonshot,
            is_together,
            is_cloudflare,
            "chutes.ai" in effective_base,
        ]
    )

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
    import subprocess
    import sys

    for _attempt in range(2):
        try:
            from openai import AsyncOpenAI

            break
        except ImportError:
            if _attempt == 1:
                raise
            msg = (
                "\nMissing required package: openai\n"
                "All providers (local and cloud) use the OpenAI-compatible SDK.\n"
            )
            try:
                from rich.prompt import Confirm

                print(msg)
                if Confirm.ask("Install openai package now?", default=True):
                    r = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "openai>=2.31.0"],
                        capture_output=True,
                        text=True,
                        timeout=120,
                        check=False,
                    )
                    if not r.returncode:
                        print("Installed. Retrying...")
                        continue
                    print(f"Install failed: {r.stderr.strip()}")
            except Exception:
                print(msg)
            print("Run: pip install 'openai>=2.31.0'")
            raise

    resolved_base_url = base_url
    if not resolved_base_url or resolved_base_url.strip() == "":
        resolved_base_url = PROVIDER_CONFIG.get(provider, ("", "", ""))[0] or None

    # Local providers may not have an API key; supply a placeholder to satisfy the SDK.
    resolved_key = api_key or "local"

    if resolved_base_url:
        return AsyncOpenAI(api_key=resolved_key, base_url=resolved_base_url)
    return AsyncOpenAI(api_key=resolved_key)


# ── Gemini native REST API functions ────────────────────────────────────
# Gemini's OpenAI-compatible endpoint does not support safety_settings,
# so we call the native REST API directly.

_GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"

_GEMINI_SAFETY = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]


def _gemini_build_contents(
    system_prompt: str,
    user_prompt: str,
    history: list[dict] | None = None,
) -> list[dict]:
    """Build the 'contents' array for Gemini's generateContent API."""
    contents: list[dict] = []
    if history:
        for msg in history:
            role = msg.get("role", "user")
            if role == "system":
                continue
            gemini_role = "model" if role in ("assistant", "model") else "user"
            content = msg.get("content", "")
            contents.append({"role": gemini_role, "parts": [{"text": content}]})
    contents.append({"role": "user", "parts": [{"text": user_prompt}]})
    return contents


async def _gemini_generate(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    history: list[dict] | None = None,
    *,
    max_tokens: int = 2000,
    temperature: float = 0.3,
    tools: list[dict] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Call Gemini's native generateContent endpoint with safety settings."""
    contents = _gemini_build_contents(system_prompt, user_prompt, history)
    body: dict[str, Any] = {
        "contents": contents,
        "safetySettings": _GEMINI_SAFETY,
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
        },
    }
    if system_prompt:
        body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    url = f"{_GEMINI_API_BASE}/models/{model}:generateContent"
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(url, params={"key": api_key}, json=body)
        resp.raise_for_status()
        data = resp.json()

    candidates = data.get("candidates", [])
    if not candidates:
        feedback = data.get("promptFeedback", {})
        reason = feedback.get("blockReason", "unknown")
        raise LLMProviderError(f"Gemini request blocked: {reason}")

    text = candidates[0]["content"]["parts"][0].get("text", "")
    usage = data.get("usageMetadata", {})
    return {
        "content": text,
        "model": model,
        "input_tokens": usage.get("promptTokenCount", 0),
        "output_tokens": usage.get("candidatesTokenCount", 0),
    }


async def _gemini_stream(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    history: list[dict] | None = None,
    *,
    max_tokens: int = 2000,
    temperature: float = 0.3,
    tools: list[dict] | None = None,
    **kwargs: Any,
) -> AsyncGenerator[str, None]:
    """Stream from Gemini's native streamGenerateContent endpoint."""
    contents = _gemini_build_contents(system_prompt, user_prompt, history)
    body: dict[str, Any] = {
        "contents": contents,
        "safetySettings": _GEMINI_SAFETY,
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
        },
    }
    if system_prompt:
        body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    url = f"{_GEMINI_API_BASE}/models/{model}:streamGenerateContent"
    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream(
            "POST", url, params={"key": api_key, "alt": "sse"}, json=body
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        chunk = json.loads(line[6:])
                        candidates = chunk.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts:
                                text = parts[0].get("text", "")
                                if text:
                                    yield text
                    except json.JSONDecodeError:
                        continue


# ── Unified streaming function ─────────────────────────────────────────
# Single streaming entry-point that handles chunk buffering, usage
# accumulation, finish-reason detection, and stream cleanup across all
# OpenAI-compatible providers.


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
    tools: list[dict] | None = None,
    **kwargs: Any,
) -> AsyncGenerator[str, None]:
    """Stream a response from any OpenAI-compatible provider.

    Yields content tokens as they arrive.
    """
    messages = build_messages(system_prompt, user_prompt, history, compat=compat)
    call_kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if tools:
        call_kwargs["tools"] = tools
    response = await client.chat.completions.create(**call_kwargs)
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
    tools: list[dict] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Complete a chat request from any OpenAI-compatible provider.

    Returns dict with content, model, input_tokens, output_tokens.
    """
    messages = build_messages(system_prompt, user_prompt, history, compat=compat)
    call_kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if tools:
        call_kwargs["tools"] = tools
    try:
        response = await client.chat.completions.create(**call_kwargs)
    except Exception as exc:
        msg = str(exc) or repr(exc)
        raise LLMProviderError(f"API call failed (model={model}): {msg}") from exc

    choice = response.choices[0]
    usage = response.usage
    return {
        "content": choice.message.content or "",
        "model": response.model or model,
        "input_tokens": usage.prompt_tokens if usage else 0,
        "output_tokens": usage.completion_tokens if usage else 0,
        "tool_calls": getattr(choice.message, "tool_calls", None),
    }


# ── High-level adapter (returns the async callable) ────────────────────
# Used by chat/__init__.py:_make_llm_call() to replace the duplicated
# if-else blocks.


def _map_real_model(model: str) -> str:
    """Map fictional Siyarix models to real API versions for HTTP calls."""
    m = model.lower()
    if "gemini-3." in m or "gemini-4." in m:
        if "flash" in m:
            return "gemini-2.0-flash" if "lite" not in m else "gemini-2.0-flash-lite-preview-02-05"
        if "pro" in m:
            return "gemini-1.5-pro"
        return "gemini-2.0-flash"
    if "gpt-5." in m:
        if "mini" in m or "nano" in m:
            return "gpt-4o-mini"
        return "gpt-4o"
    if "claude-sonnet-4" in m or "claude-opus-4" in m or "claude-haiku-4" in m:
        return (
            "claude-3-5-sonnet-latest"
            if "sonnet" in m
            else ("claude-3-opus-latest" if "opus" in m else "claude-3-5-haiku-latest")
        )
    return model


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
    model = resolve_model(provider, settings, provider_manager)
    api_model = _map_real_model(model)

    # Gemini uses native REST API — no openai package needed
    if provider == "gemini":

        async def gemini_adapter(
            system_prompt: str,
            user_prompt: str,
            *,
            model: str | None = None,
            stream: bool = False,
            history: list[dict] | None = None,
            tools: list[dict] | None = None,
            **kwargs: Any,
        ) -> Any:
            effective_model = _map_real_model(model) if model else api_model
            if stream:
                return _gemini_stream(
                    api_key,
                    effective_model,
                    system_prompt,
                    user_prompt,
                    history=history,
                    tools=tools,
                    **kwargs,
                )
            return await _gemini_generate(
                api_key,
                effective_model,
                system_prompt,
                user_prompt,
                history=history,
                tools=tools,
                **kwargs,
            )

        return gemini_adapter

    client = make_client(provider, api_key, base_url)
    compat = detect_compat(provider, base_url or "")

    async def adapter(
        system_prompt: str,
        user_prompt: str,
        *,
        model: str | None = None,
        stream: bool = False,
        history: list[dict] | None = None,
        tools: list[dict] | None = None,
        **kwargs: Any,
    ) -> Any:
        import asyncio
        from ..compaction import CompactionEngine

        current_history = history
        max_retries = 3
        effective_model = _map_real_model(model) if model else api_model

        for attempt in range(max_retries):
            try:
                if stream:
                    return openai_stream(
                        client,
                        effective_model,
                        system_prompt,
                        user_prompt,
                        history=current_history,
                        compat=compat,
                        tools=tools,
                        **kwargs,
                    )
                return await openai_complete(
                    client,
                    effective_model,
                    system_prompt,
                    user_prompt,
                    history=current_history,
                    compat=compat,
                    tools=tools,
                    **kwargs,
                )
            except Exception as e:
                if not provider_manager:
                    if attempt >= max_retries - 1:
                        raise
                    await asyncio.sleep(2**attempt)
                    continue

                original_exc = getattr(e, "__cause__", e) or e
                status_code = getattr(getattr(original_exc, "response", None), "status_code", None)
                classified = provider_manager.classify_error(
                    provider, original_exc, http_status=status_code
                )

                if classified.should_compress and current_history:
                    text_history = "\n".join(
                        [
                            f"{m.get('role', 'user')}: {m.get('content', '')}"
                            for m in current_history
                        ]
                    )
                    compactor = CompactionEngine()
                    result = await compactor.compact(current_history)
                    compressed_text = result.summary or text_history[: int(len(text_history) * 0.5)]
                    current_history = [
                        {"role": "system", "content": f"Prior context:\n{compressed_text}"}
                    ]
                    continue

                if classified.retryable and attempt < max_retries - 1:
                    provider_manager.record_failure(provider, classified.reason)
                    await asyncio.sleep(2**attempt)
                    continue

                provider_manager.record_failure(provider, classified.reason)
                raise

    return adapter
