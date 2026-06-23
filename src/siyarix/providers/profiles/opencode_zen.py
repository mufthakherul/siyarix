from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── OpenCode Zen ───────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="opencode-zen",
            display_name="OpenCode Zen",
            models=[
                ModelInfo("deepseek-v4-pro", context_window=1000000, cost_tier=CostTier.MEDIUM),
                ModelInfo("deepseek-v4-flash", context_window=1000000, cost_tier=CostTier.LOW),
                ModelInfo("deepseek-v4-flash-free", context_window=1000000, cost_tier=CostTier.FREE),
            ],
            default_model="deepseek-v4-flash",
            api_key_env="OPENCODE_API_KEY",
            base_url="https://opencode.ai/zen/v1",
            max_context_tokens=1000000,
            supports_streaming=True,
            priority=5,
            cost_tier=CostTier.LOW,
            docs_url="https://opencode.ai",
        )
    )
