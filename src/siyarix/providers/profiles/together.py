from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Together AI ────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="together",
            display_name="Together AI",
            models=[
                ModelInfo(
                    "meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8",
                    supports_vision=True,
                    context_window=512000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
                    supports_vision=True,
                    context_window=131072,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "meta-llama/Llama-3.3-70B-Instruct-Turbo",
                    context_window=131072,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "deepseek-ai/DeepSeek-V4-Pro", context_window=1000000, cost_tier=CostTier.MEDIUM
                ),
                ModelInfo(
                    "deepseek-ai/DeepSeek-V3.1", context_window=128000, cost_tier=CostTier.LOW
                ),
                ModelInfo(
                    "moonshotai/Kimi-K2.6",
                    supports_vision=True,
                    context_window=262144,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "Qwen/Qwen2.5-7B-Instruct-Turbo", context_window=32768, cost_tier=CostTier.FREE
                ),
                ModelInfo("zai-org/GLM-5.1", context_window=202800, cost_tier=CostTier.LOW),
            ],
            api_key_env="TOGETHER_API_KEY",
            max_context_tokens=512000,
            supports_streaming=True,
            supports_vision=True,
            priority=7,
            cost_tier=CostTier.LOW,
            docs_url="https://docs.together.ai/docs/inference-models",
        )
    )
