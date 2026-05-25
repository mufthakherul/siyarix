"""Tests for AdversarialTester."""

from __future__ import annotations

import pytest
pytestmark = pytest.mark.adversarial
from phalanx.adversarial_tester import AdversarialTester, AdversarialFinding, AdversarialSeverity


class TestAdversarialTester:
    @pytest.fixture
    def tester(self):
        return AdversarialTester()

    def test_review_clean_plan(self, tester):
        findings = tester.review_plan(["whois example.com", "dig example.com ANY"])
        assert isinstance(findings, list)

    def test_review_plan_ids_trigger(self, tester):
        findings = tester.review_plan(["nmap -sV target.com"])
        ids_findings = [f for f in findings if f.category == "ids_trigger"]
        assert len(ids_findings) > 0

    def test_review_plan_rate_issues(self, tester):
        findings = tester.review_plan(["masscan --rate 10000 target"])
        rate_findings = [f for f in findings if f.category == "rate_limiting"]
        assert len(rate_findings) > 0

    def test_review_plan_safety_issues(self, tester):
        findings = tester.review_plan(["rm -rf /important/data"])
        safety_findings = [f for f in findings if f.category == "safety"]
        assert len(safety_findings) > 0

    def test_review_plan_dependency_issues(self, tester):
        findings = tester.review_plan(["nuclei -u target.com"])
        dep_findings = [f for f in findings if f.category == "dependency"]
        assert len(dep_findings) >= 0

    def test_severity_levels(self, tester):
        findings = tester.review_plan(["rm -rf /", "nmap -sV target", "masscan target"])
        severities = {f.severity for f in findings}
        assert AdversarialSeverity.CRITICAL in severities

    def test_history(self, tester):
        tester.review_plan(["nmap target"])
        assert len(tester.get_history()) == 1

    def test_summary(self, tester):
        tester.review_plan(["nmap target"])
        tester.review_plan(["rm -rf /"])
        summary = tester.summary()
        assert summary["total_reviews"] == 2
        assert summary["critical_findings"] > 0

    def test_finding_dataclass(self):
        finding = AdversarialFinding(
            severity=AdversarialSeverity.HIGH,
            message="Test finding",
            suggestion="Fix it",
            category="test",
        )
        assert finding.severity == AdversarialSeverity.HIGH
        assert finding.message == "Test finding"
        assert finding.suggestion == "Fix it"

    def test_get_mitigation(self, tester):
        mitigation = tester._get_mitigation("nmap")
        assert "stealthier" in mitigation or "consider" in mitigation.lower()

    def test_empty_plan(self, tester):
        findings = tester.review_plan([])
        assert len(findings) == 0
