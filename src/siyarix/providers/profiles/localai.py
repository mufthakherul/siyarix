from __future__ import annotations
from ..types import ProviderProfile, CostTier, ProviderType
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── LocalAI (Local) ──────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="localai",
            display_name="LocalAI",
            models=[],
            base_url="http://localhost:8080",
            max_context_tokens=8192,
            supports_streaming=True,
            supports_tools=False,
            priority=3,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.LOCAL,
            docs_url="https://localai.io",
        )
    )
