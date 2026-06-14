from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Perplexity ─────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="perplexity",
            display_name="Perplexity",
            models=[
                ModelInfo(
                    "sonar-pro",
                    supports_structured_output=False,
                    context_window=200000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "sonar",
                    supports_structured_output=False,
                    context_window=128000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "sonar-reasoning-pro",
                    supports_structured_output=False,
                    context_window=128000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "sonar-reasoning",
                    supports_structured_output=False,
                    context_window=128000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "sonar-deep-research",
                    supports_structured_output=False,
                    context_window=128000,
                    cost_tier=CostTier.HIGH,
                ),
            ],
            api_key_env="PERPLEXITY_API_KEY",
            base_url="https://api.perplexity.ai",
            max_context_tokens=200000,
            supports_streaming=True,
            priority=6,
            cost_tier=CostTier.MEDIUM,
            docs_url="https://docs.perplexity.ai/docs/model-cards",
        )
    )
