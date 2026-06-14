from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── xAI / Grok ────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="xai",
            display_name="xAI (Grok)",
            models=[
                ModelInfo(
                    "grok-4.3",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=1000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "grok-4.1-fast",
                    supports_vision=True,
                    supports_structured_output=False,
                    context_window=2000000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "grok-4.20-beta-latest-reasoning",
                    supports_vision=True,
                    supports_structured_output=False,
                    context_window=2000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "grok-4.20-beta-latest-non-reasoning",
                    supports_vision=True,
                    supports_structured_output=False,
                    context_window=2000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "grok-4.20",
                    supports_vision=True,
                    supports_structured_output=False,
                    context_window=2000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "grok-build-0.1",
                    supports_vision=True,
                    supports_structured_output=False,
                    context_window=256000,
                    cost_tier=CostTier.LOW,
                ),
            ],
            api_key_env="XAI_API_KEY",
            base_url="https://api.x.ai",
            max_context_tokens=2000000,
            supports_streaming=True,
            supports_vision=True,
            priority=7,
            cost_tier=CostTier.MEDIUM,
            docs_url="https://docs.x.ai/docs",
        )
    )
