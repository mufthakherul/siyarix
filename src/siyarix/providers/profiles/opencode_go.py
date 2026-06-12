from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier


def register_profile(manager) -> None:
    # Adjust indentation

    # ── OpenCode Go ───────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="opencode-go",
            display_name="OpenCode Go",
            models=[
                ModelInfo("deepseek-v4-pro", context_window=1000000, cost_tier=CostTier.MEDIUM),
                ModelInfo("deepseek-v4-flash", context_window=1000000, cost_tier=CostTier.LOW),
            ],
            default_model="deepseek-v4-flash",
            api_key_env="OPENCODE_API_KEY",
            base_url="https://opencode.ai/zen/go/v1",
            max_context_tokens=1000000,
            supports_streaming=True,
            priority=5,
            cost_tier=CostTier.LOW,
            docs_url="https://opencode.ai",
        )
    )
