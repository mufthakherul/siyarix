from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier


def register_profile(manager) -> None:
    # Adjust indentation

    # ── Fireworks AI ──────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="fireworks",
            display_name="Fireworks AI",
            models=[
                ModelInfo(
                    "accounts/fireworks/models/kimi-k2p6",
                    supports_vision=True,
                    context_window=262144,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "accounts/fireworks/routers/kimi-k2p5-turbo",
                    supports_vision=True,
                    context_window=256000,
                    cost_tier=CostTier.LOW,
                ),
            ],
            default_model="accounts/fireworks/routers/kimi-k2p5-turbo",
            api_key_env="FIREWORKS_API_KEY",
            base_url="https://api.fireworks.ai/inference/v1",
            max_context_tokens=262144,
            supports_streaming=True,
            supports_vision=True,
            priority=6,
            cost_tier=CostTier.LOW,
            docs_url="https://fireworks.ai/models",
        )
    )
