from __future__ import annotations

from ..manager import ProviderManager
from ..types import CostTier, ModelInfo, ProviderProfile


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── DeepSeek ───────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="deepseek",
            display_name="DeepSeek",
            models=[
                ModelInfo(
                    "deepseek-v4-pro",
                    supports_tools=True,
                    supports_structured_output=False,
                    context_window=1000000,
                    cost_tier=CostTier.MEDIUM,
                ),
                ModelInfo(
                    "deepseek-v4-flash",
                    supports_tools=True,
                    context_window=1000000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "deepseek-v3.2",
                    supports_tools=True,
                    context_window=128000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo(
                    "deepseek-r1",
                    supports_tools=False,
                    context_window=128000,
                    cost_tier=CostTier.LOW,
                ),
                ModelInfo("deepseek-chat", context_window=131072, cost_tier=CostTier.LOW),
                ModelInfo(
                    "deepseek-reasoner",
                    supports_tools=False,
                    context_window=131072,
                    cost_tier=CostTier.LOW,
                ),
            ],
            api_key_env="DEEPSEEK_API_KEY",
            base_url="https://api.deepseek.com",
            max_context_tokens=1000000,
            supports_streaming=True,
            priority=8,
            cost_tier=CostTier.LOW,
            docs_url="https://platform.deepseek.com/docs",
        )
    )
