from __future__ import annotations
import enum
import time
from dataclasses import dataclass, field


class FailoverReason(enum.Enum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    BILLING = "billing"
    TIMEOUT = "timeout"
    SERVER_ERROR = "server_error"
    CONTEXT_OVERFLOW = "context_overflow"
    MODEL_NOT_FOUND = "model_not_found"
    UNKNOWN = "unknown"


@dataclass
class ClassifiedError:
    reason: FailoverReason
    retryable: bool = True
    should_rotate_credential: bool = False
    should_fallback: bool = False
    should_compress: bool = False
    message: str = ""


@dataclass
class ProviderCredential:
    provider: str
    api_key: str = ""
    base_url: str = ""
    status: str = "active"
    cooldown_until: float = 0.0
    failure_count: int = 0
    last_used: float = 0.0

    @property
    def is_available(self) -> bool:
        if self.status == "dead":
            return False
        if self.cooldown_until > time.time():
            return False
        return bool(self.api_key) or bool(self.base_url)


class CostTier(enum.StrEnum):
    FREE = "free"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def sort_key(self) -> int:
        return {"free": 0, "low": 1, "medium": 2, "high": 3}.get(self.value, 99)


class ProviderType(enum.StrEnum):
    CLOUD = "cloud"
    LOCAL = "local"


@dataclass
class ModelInfo:
    name: str
    supports_vision: bool = False
    supports_tools: bool = True
    supports_structured_output: bool = False
    supports_function_calling: bool = True
    context_window: int = 8192
    cost_tier: CostTier = CostTier.MEDIUM


@dataclass
class ProviderProfile:
    name: str
    display_name: str = ""
    models: list[ModelInfo] = field(default_factory=list)
    default_model: str = ""
    api_key_env: str = ""
    base_url: str = ""
    supports_streaming: bool = True
    supports_tools: bool = True
    supports_vision: bool = False
    supports_structured_output: bool = False
    sdk_dependency: str = ""
    max_tokens: int = 4096
    max_context_tokens: int = 128000
    priority: int = 0
    cost_tier: CostTier = CostTier.MEDIUM
    provider_type: ProviderType = ProviderType.CLOUD
    fallback_models: list[str] = field(default_factory=list)
    docs_url: str = ""

    def __post_init__(self) -> None:
        if not self.display_name:
            self.display_name = self.name.title()
        if not self.default_model and self.models:
            self.default_model = self.models[0].name
        if self.models and not self.fallback_models:
            self.fallback_models = [m.name for m in self.models[1:]]
        if self.models:
            self.supports_structured_output = any(m.supports_structured_output for m in self.models)
            self.supports_vision = any(m.supports_vision for m in self.models)
            self.supports_tools = any(m.supports_tools for m in self.models)

    def get_model_names(self) -> list[str]:
        return [m.name for m in self.models]
