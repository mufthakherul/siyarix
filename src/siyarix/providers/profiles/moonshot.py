from __future__ import annotations

from ..manager import ProviderManager
from ..types import CostTier, ModelInfo, ProviderProfile


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Moonshot / Kimi ───────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="moonshot",
            display_name="Moonshot (Kimi)",
            models=[
                ModelInfo(
                    "kimi-k2.7-code",
                    supports_vision=True,
                    context_window=262144,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "kimi-k2.6", supports_vision=True, context_window=262144, cost_tier=CostTier.LOW
                ),
                ModelInfo(
                    "kimi-k2.5", supports_vision=True, context_window=262144, cost_tier=CostTier.LOW
                ),
                ModelInfo("kimi-k2-thinking", context_window=262144, cost_tier=CostTier.LOW),
                ModelInfo("kimi-k2-thinking-turbo", context_window=262144, cost_tier=CostTier.LOW),
                ModelInfo("kimi-k2-turbo", context_window=256000, cost_tier=CostTier.LOW),
            ],
            default_model="kimi-k2.6",
            api_key_env="MOONSHOT_API_KEY",
            base_url="https://api.moonshot.ai/v1",
            max_context_tokens=262144,
            supports_streaming=True,
            supports_vision=True,
            priority=5,
            cost_tier=CostTier.LOW,
            docs_url="https://platform.moonshot.ai",
        )
    )
