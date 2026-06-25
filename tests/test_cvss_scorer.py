from __future__ import annotations
from siyarix.cvss_scorer import CVSSResult, CVSSScorer, CVSSVector, Severity
import pytest

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for CVSSScorer."""


pytestmark = pytest.mark.cvss


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
        finding = {
            "title": "Info disclosure",
            "severity": "low",
            "description": "Banner grabbing",
        }
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


class TestCVSSCore:
    """Cover missing cvss_scorer.py lines: edge cases in score calculations."""

    def test_score_without_vector_creates_default(self):
        scorer = CVSSScorer()
        result = scorer.score()
        assert result.score > 0

    def test_score_with_overrides(self):
        scorer = CVSSScorer()
        result = scorer.score(attack_vector="physical", scope="changed")
        assert result.vector.attack_vector == "physical"
        assert result.vector.scope == "changed"

    def test_score_base_zero_when_impact_zero(self):
        scorer = CVSSScorer()
        result = scorer.score(
            confidentiality="none",
            integrity="none",
            availability="none",
        )
        assert result.score == 0.0

    def test_score_from_cve(self):
        scorer = CVSSScorer()
        result = scorer.score_from_cve("CVE-2023-1234", "remote code execution vulnerability")
        assert result.score > 0

    def test_parse_vector_string(self):
        scorer = CVSSScorer()
        v = scorer.parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert v.attack_vector == "network"
        assert v.confidentiality == "high"


# ═══════════════════════════════════════════════════════════════════
# dlp.py (70% - missing 38, 42-50, 51, 61-66)
# ═══════════════════════════════════════════════════════════════════
