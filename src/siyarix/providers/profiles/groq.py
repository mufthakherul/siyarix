from __future__ import annotations

from ..manager import ProviderManager
from ..types import CostTier, ModelInfo, ProviderProfile


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Groq ───────────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="groq",
            display_name="Groq",
            models=[
                ModelInfo(
                    "groq/compound",
                    supports_tools=True,
                    context_window=131072,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "groq/compound-mini",
                    supports_tools=True,
                    context_window=131072,
                    cost_tier=CostTier.FREE,
                ),
                ModelInfo(
                    "llama-4-scout-17b-16e-instruct",
                    supports_vision=True,
                    context_window=262144,
                    cost_tier=CostTier.FREE,
                ),
                ModelInfo(
                    "llama-4-maverick-17b-128e-instruct",
                    supports_vision=True,
                    context_window=131072,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo("llama-3.3-70b-versatile", context_window=32768, cost_tier=CostTier.LOW),
                ModelInfo("llama-3.1-8b-instant", context_window=128000, cost_tier=CostTier.FREE),
                ModelInfo("mixtral-8x7b-32768", context_window=32768, cost_tier=CostTier.FREE),
                ModelInfo("openai/gpt-oss-120b", context_window=128000, cost_tier=CostTier.LOW),
                ModelInfo("openai/gpt-oss-20b", context_window=128000, cost_tier=CostTier.FREE),
                ModelInfo("qwen/qwen3-32b", context_window=128000, cost_tier=CostTier.FREE),
                ModelInfo(
                    "deepseek-r1-distill-llama-70b",
                    context_window=131072,
                    cost_tier=CostTier.FREE,
                ),
            ],
            api_key_env="GROQ_API_KEY",
            max_context_tokens=262144,
            supports_streaming=True,
            priority=8,
            cost_tier=CostTier.FREE,
            docs_url="https://console.groq.com/docs/models",
        )
    )
