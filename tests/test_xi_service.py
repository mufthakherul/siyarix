"""Tests for the XI Core Service."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from phalanx.core.intent_router import IntentRoute, RiskTier
from phalanx.core.session_kernel import OperationCard, SessionContext
from phalanx.xi.service import XICoreService, XIRecommendation


class TestXICoreService:
    """Test suite for XICoreService."""

    @pytest.fixture
    def service(self):
        return XICoreService()

    @pytest.fixture
    def session(self):
        session = MagicMock(spec=SessionContext)
        session.operations = []
        return session

    def test_recommend_high_risk(self, service, session):
        route = IntentRoute(intent="test", risk_tier=RiskTier.HIGH, metadata={})
        recs = service.recommend(session, route)
        assert any("dry-run" in r.title.lower() for r in recs)

    def test_recommend_no_target(self, service, session):
        route = IntentRoute(intent="test", risk_tier=RiskTier.LOW, metadata={"targets": []})
        recs = service.recommend(session, route)
        assert any("target" in r.title.lower() for r in recs)

    def test_recommend_resume_operation(self, service):
        session = MagicMock(spec=SessionContext)
        op = MagicMock(spec=OperationCard)
        op.state = "running"
        op.operation_id = "op_123"
        session.operations = [op]
        route = IntentRoute(intent="test", risk_tier=RiskTier.LOW, metadata={})
        recs = service.recommend(session, route)
        assert any("resume" in r.title.lower() for r in recs)

    def test_no_resume_if_completed(self, service, session):
        op = MagicMock(spec=OperationCard)
        op.state = "completed"
        session.operations = [op]
        route = IntentRoute(intent="test", risk_tier=RiskTier.LOW, metadata={})
        recs = service.recommend(session, route)
        resume_recs = [r for r in recs if "resume" in r.title.lower()]
        assert len(resume_recs) == 0

    def test_recommendation_dataclass(self):
        rec = XIRecommendation(
            title="Enable stealth mode",
            reason="High-risk target detected",
            priority="high",
            metadata={"target": "example.com"},
        )
        assert rec.title == "Enable stealth mode"
        assert rec.priority == "high"
        assert rec.metadata["target"] == "example.com"
