from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier


def register_profile(manager) -> None:
    # Adjust indentation

    # ── Z.AI (GLM) ────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="zai",
            display_name="Z.AI (GLM)",
            models=[
                ModelInfo("glm-5.1", context_window=202800, cost_tier=CostTier.LOW),
                ModelInfo("glm-5", context_window=202800, cost_tier=CostTier.LOW),
                ModelInfo("glm-5-turbo", context_window=202800, cost_tier=CostTier.LOW),
                ModelInfo(
                    "glm-5v-turbo",
                    supports_vision=True,
                    context_window=202800,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo("glm-4.7", context_window=204800, cost_tier=CostTier.LOW),
                ModelInfo("glm-4.7-flash", context_window=200000, cost_tier=CostTier.FREE),
                ModelInfo(
                    "glm-4.6v", supports_vision=True, context_window=128000, cost_tier=CostTier.LOW
                ),
            ],
            default_model="glm-5",
            api_key_env="ZAI_API_KEY",
            base_url="https://api.z.ai/api/paas/v4",
            max_context_tokens=202800,
            supports_streaming=True,
            priority=6,
            cost_tier=CostTier.LOW,
            docs_url="https://z.ai/docs",
        )
    )
