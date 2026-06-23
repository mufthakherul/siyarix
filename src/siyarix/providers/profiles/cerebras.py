from __future__ import annotations

from ..manager import ProviderManager
from ..types import CostTier, ModelInfo, ProviderProfile


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Cerebras ──────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="cerebras",
            display_name="Cerebras",
            models=[
                ModelInfo("zai-glm-4.7", context_window=128000, cost_tier=CostTier.LOW),
                ModelInfo("gpt-oss-120b", context_window=128000, cost_tier=CostTier.LOW),
                ModelInfo("gpt-oss-20b", context_window=128000, cost_tier=CostTier.FREE),
                ModelInfo(
                    "qwen-3-235b-a22b-instruct-2507", context_window=128000, cost_tier=CostTier.LOW
                ),
                ModelInfo("llama3.1-8b", context_window=128000, cost_tier=CostTier.FREE),
                ModelInfo("llama-3.3-70b", context_window=128000, cost_tier=CostTier.LOW),
                ModelInfo("kimi-k2.7-code", context_window=131072, cost_tier=CostTier.LOW),
            ],
            default_model="zai-glm-4.7",
            api_key_env="CEREBRAS_API_KEY",
            base_url="https://api.cerebras.ai/v1",
            max_context_tokens=128000,
            supports_streaming=True,
            priority=6,
            cost_tier=CostTier.LOW,
            docs_url="https://cerebras.ai/inference",
        )
    )
