from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── OpenRouter ─────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="openrouter",
            display_name="OpenRouter",
            models=[
                ModelInfo(
                    "openai/gpt-5.4",
                    supports_vision=True,
                    context_window=272000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "openai/gpt-5.5",
                    supports_vision=True,
                    context_window=1000000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "anthropic/claude-opus-4.8",
                    supports_vision=True,
                    context_window=1048576,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "anthropic/claude-sonnet-4.6",
                    supports_vision=True,
                    context_window=200000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "google/gemini-2.5-pro",
                    supports_vision=True,
                    context_window=1048576,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "deepseek/deepseek-v4-flash", context_window=1000000, cost_tier=CostTier.LOW
                ),
                ModelInfo(
                    "deepseek/deepseek-v4-pro",
                    context_window=1000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "meta-llama/llama-4-scout-17b-16e-instruct",
                    supports_vision=True,
                    context_window=262144,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "nvidia/nemotron-3-super-120b:free",
                    context_window=1000000,
                    cost_tier=CostTier.FREE,
                ),
                ModelInfo("minimax/minimax-m2.7", context_window=204000, cost_tier=CostTier.LOW),
                ModelInfo("ai21/jamba-large-1.7", context_window=256000, cost_tier=CostTier.LOW),
                ModelInfo("qwen/qwen3.5-9b", context_window=32768, cost_tier=CostTier.FREE),
                ModelInfo("z-ai/glm-5.1", context_window=202800, cost_tier=CostTier.LOW),
            ],
            api_key_env="OPENROUTER_API_KEY",
            max_context_tokens=2000000,
            supports_streaming=True,
            supports_vision=True,
            priority=6,
            cost_tier=CostTier.MEDIUM,
            docs_url="https://openrouter.ai/models",
        )
    )
