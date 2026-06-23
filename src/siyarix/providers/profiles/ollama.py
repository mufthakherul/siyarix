from __future__ import annotations

from ..manager import ProviderManager
from ..types import CostTier, ModelInfo, ProviderProfile, ProviderType


def register_profile(manager: ProviderManager) -> None:
    # Adjust indentation

    # ── Ollama (Local) ─────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="ollama",
            display_name="Ollama (Local)",
            models=[
                ModelInfo("llama3.3", context_window=131072, cost_tier=CostTier.FREE),
                ModelInfo("llama3.1", context_window=8192, cost_tier=CostTier.FREE),
                ModelInfo("mistral", context_window=8192, cost_tier=CostTier.FREE),
                ModelInfo("codellama", context_window=16384, cost_tier=CostTier.FREE),
                ModelInfo("phi4", context_window=16384, cost_tier=CostTier.FREE),
                ModelInfo("qwen2.5", context_window=32768, cost_tier=CostTier.FREE),
                ModelInfo("deepseek-r1", context_window=131072, cost_tier=CostTier.FREE),
                ModelInfo("gemma3", context_window=8192, cost_tier=CostTier.FREE),
            ],
            base_url="http://localhost:11434",
            max_context_tokens=131072,
            supports_streaming=False,
            supports_tools=False,
            supports_vision=True,
            priority=5,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.LOCAL,
        )
    )
