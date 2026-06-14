from __future__ import annotations
from ..types import ProviderProfile, CostTier
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Hugging Face ──────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="huggingface",
            display_name="Hugging Face",
            models=[],
            api_key_env="HF_TOKEN",
            base_url="https://api-inference.huggingface.co/v1",
            max_context_tokens=128000,
            supports_streaming=True,
            priority=4,
            cost_tier=CostTier.FREE,
            docs_url="https://huggingface.co/docs/api-inference/index",
        )
    )
