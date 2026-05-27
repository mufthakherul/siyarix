"""XI (Experience Intelligence) core recommendations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.intent_router import IntentRoute, RiskTier
from ..core.session_kernel import SessionContext


@dataclass
class XIRecommendation:
    """Single XI recommendation item."""

    title: str
    reason: str
    priority: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)


class XICoreService:
    """Generate context-aware recommendations and next actions."""

    def recommend(
        self, session: SessionContext, route: IntentRoute
    ) -> list[XIRecommendation]:
        recs: list[XIRecommendation] = []

        if route.risk_tier == RiskTier.HIGH:
            recs.append(
                XIRecommendation(
                    title="Enable dry-run for high-risk instruction",
                    reason="Detected high-risk intent category requiring safer preview flow.",
                    priority="high",
                )
            )

        if not route.metadata.get("targets"):
            recs.append(
                XIRecommendation(
                    title="Set explicit target scope",
                    reason="No explicit target detected; scope lock improves operational safety.",
                    priority="high",
                )
            )

        if session.operations and session.operations[-1].state not in {
            "completed",
            "failed",
        }:
            recs.append(
                XIRecommendation(
                    title="Resume active operation",
                    reason="Previous operation is still in progress and can be resumed.",
                    priority="medium",
                    metadata={"operation_id": session.operations[-1].operation_id},
                )
            )

        return recs
