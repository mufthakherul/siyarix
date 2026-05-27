"""Tests for ComplianceRunner."""

from __future__ import annotations

import pytest

from siyarix.compliance_runner import (ComplianceControl, ComplianceFramework,
                                       ComplianceResult, ComplianceRunner)

pytestmark = pytest.mark.compliance


class TestComplianceRunner:
    @pytest.fixture
    def runner(self):
        return ComplianceRunner()

    def test_assess_pci_dss(self, runner):
        result = runner.assess(ComplianceFramework.PCI_DSS, target="example.com")
        assert result.framework == ComplianceFramework.PCI_DSS
        assert len(result.controls) > 0
        assert result.assessment_id.startswith("ASSESS-")

    def test_assess_iso_27001(self, runner):
        result = runner.assess(ComplianceFramework.ISO_27001)
        assert len(result.controls) > 0

    def test_assess_nist(self, runner):
        result = runner.assess(ComplianceFramework.NIST_800_53)
        assert len(result.controls) > 0

    def test_assess_soc2(self, runner):
        result = runner.assess(ComplianceFramework.SOC_2)
        assert len(result.controls) > 0

    def test_assess_gdpr(self, runner):
        result = runner.assess(ComplianceFramework.GDPR)
        assert len(result.controls) > 0

    def test_assess_hipaa(self, runner):
        result = runner.assess(ComplianceFramework.HIPAA)
        assert len(result.controls) > 0

    def test_assess_all(self, runner):
        results = runner.assess_all(target="example.com")
        assert len(results) == len(ComplianceFramework)
        for fw in ComplianceFramework:
            assert fw.value in results

    def test_controls_have_required_fields(self, runner):
        result = runner.assess(ComplianceFramework.PCI_DSS)
        for control in result.controls:
            assert control.control_id
            assert control.title
            assert control.severity
            assert control.compliant is not None

    def test_frameworks_summary(self, runner):
        runner.assess(ComplianceFramework.PCI_DSS)
        runner.assess(ComplianceFramework.ISO_27001)
        summary = runner.get_frameworks_summary()
        assert summary["total_assessments"] == 2

    def test_control_dataclass(self):
        control = ComplianceControl(
            control_id="TEST-1", title="Test Control", compliant=True
        )
        assert control.control_id == "TEST-1"
        assert control.compliant is True
        assert control.applicable is True

    def test_result_dataclass(self):
        result = ComplianceResult(
            framework=ComplianceFramework.PCI_DSS, target="example.com"
        )
        assert result.framework == ComplianceFramework.PCI_DSS
        assert result.assessment_id == ""
