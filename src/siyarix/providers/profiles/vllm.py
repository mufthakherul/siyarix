from __future__ import annotations
from ..types import ProviderProfile, CostTier, ProviderType


def register_profile(manager) -> None:
    # Adjust indentation

    # ── vLLM (Local) ──────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="vllm",
            display_name="vLLM",
            models=[],
            base_url="http://localhost:8000",
            max_context_tokens=32768,
            supports_streaming=True,
            supports_tools=True,
            priority=3,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.LOCAL,
            docs_url="https://docs.vllm.ai",
        )
    )
