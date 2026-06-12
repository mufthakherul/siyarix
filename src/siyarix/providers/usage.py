from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any
from .types import CostTier

logger = logging.getLogger(__name__)


class UsageRecord:
    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    call_count: int = 0
    total_cost_estimated: float = 0.0

    def record(
        self, input_tokens: int, output_tokens: int, cost_tier: CostTier = CostTier.MEDIUM
    ) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.call_count += 1
        rates = {
            CostTier.FREE: 0.0,
            CostTier.LOW: 0.15e-6,
            CostTier.MEDIUM: 2.0e-6,
            CostTier.HIGH: 10.0e-6,
        }
        rate = rates.get(cost_tier, 2.0e-6)
        self.total_cost_estimated += (input_tokens + output_tokens * 4) * rate

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "call_count": self.call_count,
            "total_cost_estimated": round(self.total_cost_estimated, 6),
        }

    @classmethod
    def from_dict(cls, d: dict) -> UsageRecord:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class UsageTracker:
    """Tracks token usage and cost per provider across a session."""

    def __init__(self, path: str | None = None) -> None:
        self._records: dict[str, UsageRecord] = {}
        self._path = path

    def record_call(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_tier: CostTier = CostTier.MEDIUM,
    ) -> None:
        key = f"{provider}/{model}"
        if key not in self._records:
            self._records[key] = UsageRecord(provider=provider, model=model)
        self._records[key].record(input_tokens, output_tokens, cost_tier)

    def summary(self) -> str:
        if not self._records:
            return "No LLM usage this session."
        total_cost = sum(r.total_cost_estimated for r in self._records.values())
        total_in = sum(r.input_tokens for r in self._records.values())
        total_out = sum(r.output_tokens for r in self._records.values())
        total_calls = sum(r.call_count for r in self._records.values())
        return (
            f"LLM calls: {total_calls} | Tokens: {total_in}↑ {total_out}↓ "
            f"| Est. cost: ${total_cost:.4f}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {k: v.to_dict() for k, v in self._records.items()}

    def save(self) -> None:
        if not self._path:
            return
        try:
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
        except Exception as exc:
            logger.debug("Failed to save usage tracker: %s", exc)

    @classmethod
    def load(cls, path: str) -> UsageTracker:
        tracker = cls(path=path)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            for key, record in data.items():
                tracker._records[key] = UsageRecord.from_dict(record)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return tracker
