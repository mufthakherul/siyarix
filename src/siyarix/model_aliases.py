from __future__ import annotations

import re

_PROVIDER_ALIASES: dict[str, dict[str, str]] = {
    "anthropic": {
        "opus": "claude-opus-4-8",
        "opus-4.8": "claude-opus-4-8",
        "opus-4.7": "claude-opus-4-7",
        "opus-4.6": "claude-opus-4-6",
        "sonnet": "claude-sonnet-4-6",
        "sonnet-4.6": "claude-sonnet-4-6",
        "haiku": "claude-haiku-4-5",
        "haiku-4.5": "claude-haiku-4-5",
    },
    "gemini": {
        "gemini-3-pro": "gemini-3.1-pro-preview",
        "gemini-3-flash": "gemini-3-flash-preview",
        "gemini-3.1-pro": "gemini-3.1-pro-preview",
    },
    "xai": {
        "grok-4-fast-reasoning": "grok-4-fast",
        "grok-4-1-fast-reasoning": "grok-4-1-fast",
        "grok-4.20-reasoning": "grok-4.20-beta-latest-reasoning",
        "grok-4.20-non-reasoning": "grok-4.20-beta-latest-non-reasoning",
    },
    "together": {
        "moonshotai/Kimi-K2.5": "moonshotai/Kimi-K2.6",
        "deepseek-ai/DeepSeek-V3.1": "deepseek-ai/DeepSeek-V4-Pro",
        "zai-org/GLM-5": "zai-org/GLM-5.1",
    },
    "openrouter": {
        "openai/gpt-5.4": "openai/gpt-5.4",
        "anthropic/claude-opus-4.8": "anthropic/claude-opus-4.8",
        "anthropic/claude-sonnet-4.6": "anthropic/claude-sonnet-4.6",
    },
    "zai": {
        "glm-5": "glm-5.1",
        "z-ai/glm-5": "glm-5.1",
        "z.ai/glm-5": "glm-5.1",
    },
    "minimax": {
        "MiniMax-M3": "MiniMax-M3",
        "MiniMax-M2.7": "MiniMax-M2.7",
        "m3": "MiniMax-M3",
        "m2.7": "MiniMax-M2.7",
    },
    "deepseek": {
        "deepseek-v4": "deepseek-v4-flash",
    },
    "azure": {
        "gpt-5.4": "gpt-5.4",
        "gpt-4.1": "gpt-4.1",
    },
}

_GOOGLE_PREVIEW_RE = re.compile(r"^gemini-(\d+)\.(\d+)(?:-(pro|flash|flash-lite))?$")
_ANTHROPIC_DOT_RE = re.compile(r"^(claude-)?(opus|sonnet|haiku)[-.](\d+)[-.](\d+)$")
_XAI_DOT_RE = re.compile(r"^grok[-.](\d+)[-.](\d+)(?:[-.](fast|reasoning|build))?$")


def normalize_model_id(provider: str | None, model_id: str) -> str:
    """Normalize a model ID, applying provider-specific aliases and syntax fixes.

    Returns the normalized model ID, or the original if no normalization applies.
    """
    if not model_id:
        return model_id

    provider = (provider or "").lower().strip()

    # 1. Check exact alias map
    if provider in _PROVIDER_ALIASES:
        if model_id in _PROVIDER_ALIASES[provider]:
            return _PROVIDER_ALIASES[provider][model_id]

    # 2. Google preview model normalization
    if provider == "gemini":
        m = _GOOGLE_PREVIEW_RE.match(model_id)
        if m:
            major, minor, variant = m.group(1), m.group(2), m.group(3)
            if int(major) >= 3:
                if variant:
                    normalized = f"gemini-{major}.{minor}-{variant}"
                    return normalized

    # 3. Anthropic: replace dots with dashes (claude-opus-4.8 → claude-opus-4-8)
    if provider == "anthropic" or provider in ("openrouter", "vercel-ai-gateway"):
        m = _ANTHROPIC_DOT_RE.match(model_id)
        if m:
            prefix = m.group(1) or "claude-"
            family = m.group(2)
            major = m.group(3)
            minor = m.group(4)
            normalized = f"{prefix}{family}-{major}-{minor}"
            return normalized

    # 4. xAI: replace dots with dashes
    if provider == "xai":
        m = _XAI_DOT_RE.match(model_id)
        if m:
            major, minor = m.group(1), m.group(2)
            suffix = f"-{m.group(3)}" if m.group(3) else ""
            normalized = f"grok-{major}-{minor}{suffix}"
            return normalized

    return model_id


def resolve_alias(provider: str | None, alias: str) -> str:
    """Resolve a short alias to a full model ID.

    Returns the full model ID, or the alias unchanged if it doesn't match.
    """
    provider = (provider or "").lower().strip()
    if provider in _PROVIDER_ALIASES:
        if alias in _PROVIDER_ALIASES[provider]:
            return _PROVIDER_ALIASES[provider][alias]
    return alias


def list_aliases(provider: str | None = None) -> dict[str, dict[str, str]]:
    """List all aliases, optionally filtered by provider."""
    if provider:
        p = provider.lower().strip()
        return {p: _PROVIDER_ALIASES.get(p, {})}
    return dict(_PROVIDER_ALIASES)


def register_alias(provider: str, alias: str, target: str) -> None:
    """Register a custom alias at runtime."""
    p = provider.lower().strip()
    if p not in _PROVIDER_ALIASES:
        _PROVIDER_ALIASES[p] = {}
    _PROVIDER_ALIASES[p][alias] = target


__all__ = [
    "normalize_model_id",
    "resolve_alias",
    "list_aliases",
    "register_alias",
]
