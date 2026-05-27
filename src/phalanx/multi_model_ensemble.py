"""Multi-model ensemble for AI-driven task planning.

Routes tasks to multiple LLM providers simultaneously and aggregates
results for optimal plan selection as described in Chapter 16.1.
Supports plan voting, hallucination detection, and cost optimization.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class VotingStrategy(str, Enum):
    MAJORITY = "majority"
    CONSENSUS = "consensus"
    WEIGHTED = "weighted"
    BEST_SCORE = "best_score"


@dataclass
class ModelResponse:
    """Response from a single model in the ensemble."""

    model_name: str = ""
    provider: str = ""
    plan: str = ""
    confidence: float = 0.0
    cost_estimate: float = 0.0
    latency_ms: float = 0.0
    tokens_used: int = 0
    error: str = ""


@dataclass
class EnsembleResult:
    """Aggregated result from the multi-model ensemble."""

    task: str = ""
    responses: list[ModelResponse] = field(default_factory=list)
    selected_plan: str = ""
    selection_reason: str = ""
    voting_strategy: VotingStrategy = VotingStrategy.WEIGHTED
    consensus_level: float = 0.0
    hallucination_risk: float = 0.0
    total_cost: float = 0.0
    total_latency_ms: float = 0.0


# Provider cost per 1K tokens
_PROVIDER_COSTS: dict[str, float] = {
    "openai": 0.01,
    "gemini": 0.0025,
    "ollama": 0.0,
    "groq": 0.005,
    "together": 0.006,
}

# Provider complexity tiers
_COMPLEXITY_TIERS: dict[str, list[str]] = {
    "simple": ["ollama", "groq"],
    "medium": ["gemini", "together"],
    "complex": ["openai"],
}


class MultiModelEnsemble:
    """Multi-model ensemble for AI task planning."""

    def __init__(self) -> None:
        self._providers: dict[str, Any] = {}
        self._response_history: list[EnsembleResult] = []

    def register_provider(self, name: str, provider_instance: Any) -> None:
        self._providers[name] = provider_instance
        logger.debug("Provider registered with ensemble: %s", name)

    def available_providers(self) -> list[str]:
        return list(self._providers.keys())

    async def plan(
        self,
        task: str,
        providers: list[str] | None = None,
        voting_strategy: VotingStrategy = VotingStrategy.WEIGHTED,
    ) -> EnsembleResult:
        selected = providers or self.available_providers()
        if not selected:
            return EnsembleResult(task=task, selection_reason="No providers available")

        result = EnsembleResult(task=task, voting_strategy=voting_strategy)
        responses = await asyncio.gather(
            *[self._query_provider(name, task) for name in selected],
            return_exceptions=True,
        )

        for name, resp in zip(selected, responses):
            if isinstance(resp, Exception):
                result.responses.append(
                    ModelResponse(model_name=name, provider=name, error=str(resp))
                )
            elif isinstance(resp, ModelResponse):
                result.responses.append(resp)

        # Select plan based on voting strategy
        result.selected_plan, result.selection_reason = self._select_plan(
            result.responses, voting_strategy
        )
        result.consensus_level = self._calculate_consensus(result.responses)
        result.hallucination_risk = self._detect_hallucinations(result.responses)
        result.total_cost = sum(r.cost_estimate for r in result.responses)
        result.total_latency_ms = sum(r.latency_ms for r in result.responses)

        self._response_history.append(result)
        return result

    def select_providers_for_task(
        self,
        task: str,
        complexity: str = "medium",
        _max_budget: float = 0.05,
    ) -> list[str]:
        tier = _COMPLEXITY_TIERS.get(complexity, _COMPLEXITY_TIERS["medium"])
        available = [p for p in tier if p in self._providers]
        if not available:
            return self.available_providers()
        return available[:2]

    def get_history(self, limit: int = 10) -> list[EnsembleResult]:
        return self._response_history[-limit:]

    def summary(self) -> dict[str, Any]:
        return {
            "registered_providers": len(self._providers),
            "provider_names": list(self._providers.keys()),
            "total_ensemble_runs": len(self._response_history),
            "avg_consensus": (
                sum(r.consensus_level for r in self._response_history)
                / max(len(self._response_history), 1)
            ),
            "total_cost": sum(r.total_cost for r in self._response_history),
        }

    async def _query_provider(self, provider_name: str, task: str) -> ModelResponse:
        import time

        start = time.monotonic()

        provider = self._providers.get(provider_name)
        if not provider:
            return ModelResponse(
                model_name=provider_name,
                error=f"Provider {provider_name} not registered",
            )

        try:
            if hasattr(provider, "plan"):
                if asyncio.iscoroutinefunction(provider.plan):
                    plan_text = await provider.plan(task)
                else:
                    plan_text = provider.plan(task)
            elif hasattr(provider, "generate"):
                if asyncio.iscoroutinefunction(provider.generate):
                    plan_text = await provider.generate(task)
                else:
                    plan_text = provider.generate(task)
            else:
                plan_text = str(provider)

            latency = (time.monotonic() - start) * 1000
            cost = _PROVIDER_COSTS.get(provider_name, 0.01)
            tokens_est = len(plan_text.split()) * 1.5  # rough estimate

            return ModelResponse(
                model_name=provider_name,
                provider=provider_name,
                plan=str(plan_text),
                confidence=0.8,
                cost_estimate=cost * tokens_est / 1000,
                latency_ms=round(latency, 1),
                tokens_used=int(tokens_est),
            )
        except Exception as exc:
            return ModelResponse(model_name=provider_name, error=str(exc))

    def _select_plan(
        self,
        responses: list[ModelResponse],
        strategy: VotingStrategy,
    ) -> tuple[str, str]:
        valid = [r for r in responses if r.plan and not r.error]
        if not valid:
            return "", "No valid responses received"

        if strategy == VotingStrategy.MAJORITY:
            from collections import Counter

            plans = [r.plan[:100] for r in valid]
            common = Counter(plans).most_common(1)
            if common:
                return (
                    valid[plans.index(common[0][0])].plan,
                    "Selected by majority vote",
                )

        if strategy == VotingStrategy.WEIGHTED:
            best = max(valid, key=lambda r: r.confidence * (1 - r.cost_estimate * 10))
            return (
                best.plan,
                f"Selected by weighted confidence ({best.model_name}, conf={best.confidence:.2f})",
            )

        if strategy == VotingStrategy.CONSENSUS:
            plans = [r.plan for r in valid]
            if len(plans) > 1 and all(p == plans[0] for p in plans):
                return plans[0], "Full consensus across all models"
            for r in valid:
                return r.plan, f"Best individual plan from {r.model_name}"

        # Default: best confidence
        best = max(valid, key=lambda r: r.confidence)
        return best.plan, f"Selected by highest confidence ({best.model_name})"

    def _calculate_consensus(self, responses: list[ModelResponse]) -> float:
        valid = [r.plan[:50] for r in responses if r.plan and not r.error]
        if len(valid) < 2:
            return 0.0
        matches = sum(
            1
            for i in range(len(valid))
            for j in range(i + 1, len(valid))
            if valid[i] == valid[j]
        )
        total = len(valid) * (len(valid) - 1) / 2
        return matches / total if total > 0 else 0.0

    def _detect_hallucinations(self, responses: list[ModelResponse]) -> float:
        valid = [r for r in responses if r.plan and not r.error]
        if len(valid) < 2:
            return 0.0
        scores = [r.confidence for r in valid]
        variance = sum((s - sum(scores) / len(scores)) ** 2 for s in scores) / len(
            scores
        )
        return min(variance * 2, 1.0)


__all__ = ["MultiModelEnsemble", "EnsembleResult", "ModelResponse", "VotingStrategy"]
