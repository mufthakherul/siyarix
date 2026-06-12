from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier


def register_profile(manager) -> None:
    # Adjust indentation

    # ── NVIDIA ────────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="nvidia",
            display_name="NVIDIA",
            models=[
                ModelInfo(
                    "nvidia/nemotron-3-super-120b-a12b",
                    context_window=1000000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "moonshotai/kimi-k2.5",
                    supports_vision=True,
                    context_window=262144,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo("minimaxai/minimax-m2.7", context_window=204000, cost_tier=CostTier.LOW),
                ModelInfo("z-ai/glm-5.1", context_window=202800, cost_tier=CostTier.LOW),
            ],
            default_model="nvidia/nemotron-3-super-120b-a12b",
            api_key_env="NVIDIA_API_KEY",
            base_url="https://integrate.api.nvidia.com/v1",
            max_context_tokens=1000000,
            supports_streaming=True,
            priority=5,
            cost_tier=CostTier.LOW,
            docs_url="https://build.nvidia.com/explore/discover",
        )
    )
