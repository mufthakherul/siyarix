# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-provider LLM abstraction with fallback and credential pooling.

Supports 24 providers with capability flags, cost tiers, and smart failover.
"""

from .types import (
    FailoverReason,
    ClassifiedError,
    ProviderCredential,
    CostTier,
    ProviderType,
    ModelInfo,
    ProviderProfile,
)
from .usage import UsageRecord, UsageTracker
from .state import ProviderStateManager
from .manager import ProviderManager, resolve_api_key, get_provider_env_var

__all__ = [
    "FailoverReason",
    "ClassifiedError",
    "ProviderCredential",
    "CostTier",
    "ProviderType",
    "ModelInfo",
    "ProviderProfile",
    "UsageRecord",
    "UsageTracker",
    "ProviderStateManager",
    "ProviderManager",
    "resolve_api_key",
    "get_provider_env_var",
]
