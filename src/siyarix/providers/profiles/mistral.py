from __future__ import annotations

from ..manager import ProviderManager
from ..types import CostTier, ModelInfo, ProviderProfile


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Mistral AI ─────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="mistral",
            display_name="Mistral AI",
            models=[
                ModelInfo(
                    "mistral-large-latest",
                    supports_vision=True,
                    supports_function_calling=True,
                    supports_structured_output=True,
                    context_window=262000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "mistral-medium-3-5",
                    supports_vision=True,
                    supports_function_calling=True,
                    context_window=262000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "mistral-small-latest",
                    supports_vision=True,
                    supports_function_calling=True,
                    context_window=128000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "codestral-latest",
                    supports_function_calling=True,
                    context_window=256000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "pixtral-large-latest",
                    supports_vision=True,
                    supports_function_calling=True,
                    context_window=128000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "devstral-medium-latest",
                    supports_function_calling=True,
                    context_window=262000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "magistral-small",
                    supports_function_calling=True,
                    context_window=128000,
                    cost_tier=CostTier.MEDIUM,
                ),
            ],
            default_model="mistral-medium-3-5",
            api_key_env="MISTRAL_API_KEY",
            base_url="https://api.mistral.ai",
            max_context_tokens=262000,
            supports_streaming=True,
            supports_vision=True,
            priority=7,
            cost_tier=CostTier.MEDIUM,
            docs_url="https://docs.mistral.ai/platform/models",
        )
    )
