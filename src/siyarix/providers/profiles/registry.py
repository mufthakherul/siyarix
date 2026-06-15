from __future__ import annotations
from ..types import ProviderProfile, CostTier, ProviderType
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    manager.register(
        ProviderProfile(
            name="registry",
            display_name="Registry (Offline)",
            api_key_env="",
            base_url="",
            supports_streaming=False,
            supports_tools=False,
            supports_vision=False,
            supports_structured_output=False,
            max_tokens=0,
            max_context_tokens=0,
            priority=0,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.LOCAL,
        )
    )
