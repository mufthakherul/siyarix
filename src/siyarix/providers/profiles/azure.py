from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier


def register_profile(manager) -> None:
    # Adjust indentation

    # ── Azure OpenAI ──────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="azure",
            display_name="Azure OpenAI",
            models=[
                ModelInfo(
                    "gpt-5.4",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=1050000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "gpt-5.4-mini",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=400000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "gpt-4.1",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=1000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "gpt-4.1-mini",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=1000000,
                    cost_tier=CostTier.LOW,
                ),
            ],
            api_key_env="AZURE_OPENAI_API_KEY",
            base_url="https://YOUR_RESOURCE.openai.azure.com",
            max_context_tokens=1050000,
            supports_streaming=True,
            supports_vision=True,
            priority=9,
            cost_tier=CostTier.HIGH,
            docs_url="https://learn.microsoft.com/en-us/azure/ai-services/openai/",
        )
    )
