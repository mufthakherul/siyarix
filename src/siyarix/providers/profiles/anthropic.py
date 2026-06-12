from __future__ import annotations
from ..types import ProviderProfile, ModelInfo, CostTier


def register_profile(manager) -> None:
    # Adjust indentation

    # ── Anthropic ───────────────────────────────────────────────────
    manager.register(
        ProviderProfile(
            name="anthropic",
            display_name="Anthropic",
            models=[
                ModelInfo(
                    "claude-opus-4-8",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=1048576,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "claude-opus-4-7",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=200000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "claude-opus-4-6",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=200000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "claude-sonnet-4-6",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=200000,
                    cost_tier=CostTier.HIGH,
                ),
                ModelInfo(
                    "claude-haiku-4-5",
                    supports_vision=True,
                    supports_structured_output=True,
                    context_window=200000,
                    cost_tier=CostTier.MEDIUM,
                ),
            ],
            api_key_env="ANTHROPIC_API_KEY",
            max_context_tokens=1048576,
            supports_streaming=True,
            supports_vision=True,
            priority=10,
            cost_tier=CostTier.HIGH,
            docs_url="https://docs.anthropic.com/en/docs/about-claude/models",
        )
    )
