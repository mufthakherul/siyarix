from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── MiniMax ───────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="minimax",
            display_name="MiniMax",
            models=[
                ModelInfo(
                    "MiniMax-M3",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=1000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo("MiniMax-M2.7", context_window=204000, cost_tier=CostTier.LOW),
                ModelInfo("MiniMax-M2.7-highspeed", context_window=204000, cost_tier=CostTier.LOW),
            ],
            default_model="MiniMax-M3",
            api_key_env="MINIMAX_API_KEY",
            base_url="https://api.minimax.io/v1",
            max_context_tokens=1000000,
            supports_streaming=True,
            supports_vision=True,
            priority=5,
            cost_tier=CostTier.MEDIUM,
            docs_url="https://platform.minimaxi.com",
        )
    )
