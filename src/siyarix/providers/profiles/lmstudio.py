from __future__ import annotations
from ..types import ProviderProfile, CostTier, ProviderType
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── LM Studio (Local) ─────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="lmstudio",
            display_name="LM Studio (Local)",
            models=[],
            base_url="http://localhost:1234",
            max_context_tokens=8192,
            supports_streaming=False,
            supports_tools=False,
            priority=4,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.LOCAL,
            docs_url="https://lmstudio.ai/docs",
        )
    )
