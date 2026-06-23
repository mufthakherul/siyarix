from __future__ import annotations

from ..manager import ProviderManager
from ..types import CostTier, ModelInfo, ProviderProfile


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── NVIDIA ────────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="nvidia",
            display_name="NVIDIA",
            models=[
                ModelInfo(
                    "nvidia/nemotron-3-ultra-550b-a55b",
                    context_window=1000000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "nvidia/nemotron-3-super-120b-a12b",
                    context_window=1000000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "nvidia/nemotron-3-nano-30b-a3b",
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
                ModelInfo(
                    "minimaxai/minimax-m3",
                    supports_vision=True,
                    context_window=1000000,
                    cost_tier=CostTier.MEDIUM,
                ),
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
