"""Tests for CVSSScorer."""

from __future__ import annotations

import pytest
pytestmark = pytest.mark.cvss
from siyarix.cvss_scorer import CVSSScorer, CVSSVector, CVSSResult, Severity


class TestCVSSScorer:
    @pytest.fixture
    def scorer(self):
        return CVSSScorer()

    def test_score_default(self, scorer):
        result = scorer.score()
        assert isinstance(result, CVSSResult)
        assert 0.0 <= result.score <= 10.0
        assert isinstance(result.severity, Severity)

    def test_score_critical(self, scorer):
        result = scorer.score(
            confidentiality="high",
            integrity="high",
            availability="high",
            attack_vector="network",
            attack_complexity="low",
        )
        assert result.score >= 9.0
        assert result.severity == Severity.CRITICAL

    def test_score_none(self, scorer):
        result = scorer.score(
            confidentiality="none",
            integrity="none",
            availability="none",
            attack_vector="physical",
            attack_complexity="high",
            privileges_required="high",
            user_interaction="required",
        )
        assert result.score == 0.0
        assert result.severity == Severity.NONE

    def test_vector_string(self, scorer):
        result = scorer.score()
        assert result.vector_string.startswith("CVSS:3.1/")

    def test_score_from_finding_critical(self, scorer):
        finding = {
            "title": "Remote Code Execution",
            "severity": "critical",
            "description": "RCE in web app",
        }
        result = scorer.score_from_finding(finding)
        assert result.score >= 7.0

    def test_score_from_finding_low(self, scorer):
        finding = {"title": "Info disclosure", "severity": "low", "description": "Banner grabbing"}
        result = scorer.score_from_finding(finding)
        assert result.score < 4.0

    def test_score_from_cve(self, scorer):
        result = scorer.score_from_cve("CVE-2023-1234", "Remote code execution in web application")
        assert result.score > 0

    def test_parse_vector_string(self, scorer):
        vector = scorer.parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert vector.attack_vector == "network"
        assert vector.attack_complexity == "low"
        assert vector.confidentiality == "high"
        assert vector.integrity == "high"
        assert vector.availability == "high"

    def test_cvss_vector_defaults(self):
        v = CVSSVector()
        assert v.attack_vector == "network"
        assert v.to_vector_string().startswith("CVSS:3.1/")

    def test_cvss_result_dataclass(self):
        result = CVSSResult(score=9.0, severity=Severity.CRITICAL)
        assert result.score == 9.0
        assert result.severity == Severity.CRITICAL

    def test_severity_thresholds(self, scorer):
        assert scorer._severity_from_score(9.5) == Severity.CRITICAL
        assert scorer._severity_from_score(8.0) == Severity.HIGH
        assert scorer._severity_from_score(5.0) == Severity.MEDIUM
        assert scorer._severity_from_score(2.0) == Severity.LOW
        assert scorer._severity_from_score(0.0) == Severity.NONE
