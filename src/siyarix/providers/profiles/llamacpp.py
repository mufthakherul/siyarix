from __future__ import annotations
from ..types import ProviderProfile, CostTier, ProviderType
from ..manager import ProviderManager


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── llama.cpp (Local) ─────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="llamacpp",
            display_name="llama.cpp",
            models=[],
            base_url="http://localhost:8080",
            max_context_tokens=8192,
            supports_streaming=True,
            supports_tools=False,
            priority=4,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.LOCAL,
            docs_url="https://github.com/ggml-org/llama.cpp",
        )
    )
