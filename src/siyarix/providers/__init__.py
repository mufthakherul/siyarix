# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-provider LLM abstraction with fallback and credential pooling.

Supports 24 providers with capability flags, cost tiers, and smart failover.
"""

from .manager import ProviderManager, get_provider_env_var, resolve_api_key
from .state import ProviderStateManager
from .types import (
    ClassifiedError,
    CostTier,
    FailoverReason,
    ModelInfo,
    ProviderCredential,
    ProviderProfile,
    ProviderType,
)
from .usage import UsageRecord, UsageTracker

__all__ = [
    "ClassifiedError",
    "CostTier",
    "FailoverReason",
    "ModelInfo",
    "ProviderCredential",
    "ProviderManager",
    "ProviderProfile",
    "ProviderStateManager",
    "ProviderType",
    "UsageRecord",
    "UsageTracker",
    "get_provider_env_var",
    "resolve_api_key",
]
