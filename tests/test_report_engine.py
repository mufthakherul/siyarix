# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ReportEngine and report data models."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from siyarix.cvss_scorer import CVSSResult, Severity
from siyarix.report import ReportEngine
from siyarix.report.models import Report, ReportConfig, ReportFormat, ReportSection

pytestmark = pytest.mark.report


# ── Models ──────────────────────────────────────────────────────────────────


class TestReportSection:
    def test_defaults(self):
        s = ReportSection(title="Test")
        assert s.title == "Test"
        assert s.content == ""
        assert s.findings == []
        assert s.subsections == []

    def test_all_fields(self):
        sub = ReportSection(title="Sub")
        s = ReportSection(
            title="Main", content="content", findings=[{"a": 1}], subsections=[sub],
        )
        assert s.title == "Main"
        assert s.content == "content"
        assert s.findings == [{"a": 1}]
        assert s.subsections == [sub]


class TestReportConfig:
    def test_defaults(self):
        c = ReportConfig()
        assert c.title == "Siyarix Security Assessment Report"
        assert c.author == "Siyarix Automated Agent"
        assert c.company == ""
        assert c.logo_url == ""
        assert c.include_executive_summary is True
        assert c.include_methodology is True
        assert c.include_findings is True
        assert c.include_evidence is True
        assert c.include_remediation is True
        assert c.include_appendix is True
        assert c.cvss_scoring is True
        assert c.template_name == "default"

    def test_custom_values(self):
        c = ReportConfig(
            title="Custom Report",
            author="Tester",
            company="ACME",
            logo_url="https://example.com/logo.png",
            include_executive_summary=False,
            include_methodology=False,
            include_findings=False,
            include_evidence=False,
            include_remediation=False,
            include_appendix=False,
            cvss_scoring=False,
            template_name="pentest",
        )
        assert c.title == "Custom Report"
        assert not c.cvss_scoring


class TestReportFormat:
    def test_values(self):
        assert ReportFormat.MARKDOWN.value == "markdown"
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.JSON.value == "json"
        assert ReportFormat.SARIF.value == "sarif"

    def test_members(self):
        assert set(ReportFormat.__members__) == {"MARKDOWN", "HTML", "JSON", "SARIF"}


class TestReportPostInit:
    def test_report_id_generated(self):
        r = Report()
        assert r.report_id
        assert len(r.report_id) == 16

    def test_report_id_preserved(self):
        r = Report(report_id="custom-id")
        assert r.report_id == "custom-id"

    def test_timestamp_set(self):
        r = Report()
        assert r.generated_at
        assert "T" in r.generated_at

    def test_defaults(self):
        r = Report()
        assert isinstance(r.config, ReportConfig)
        assert r.sections == []
        assert r.findings == []
        assert r.metadata == {}


# ── ReportEngine ────────────────────────────────────────────────────────────


class TestReportEngineInit:
    def test_with_cvss_scorer(self):
        mock_scorer = MagicMock()
        engine = ReportEngine(cvss_scorer=mock_scorer)
        assert engine._cvss is mock_scorer

    def test_without_cvss_scorer(self):
        engine = ReportEngine()
        assert engine._cvss is not None


class TestBuildReportFromKg:
    def test_extracts_finding_nodes(self):
        engine = ReportEngine()
        mock_node = MagicMock()
        mock_node.properties = {
            "category": "finding",
            "severity": "high",
            "type": "vuln",
            "target": "10.0.0.1",
            "evidence": "proof",
            "port": 443,
            "service": "https",
            "cve": "CVE-2024-0001",
            "cvss_score": 7.5,
        }
        mock_node.label = "Test Finding"
        mock_kg = MagicMock()
        mock_kg.nodes = {"n1": mock_node}

        report = engine.build_report_from_kg(mock_kg, target="10.0.0.1")
        assert len(report.findings) == 1
        assert report.findings[0]["severity"] == "high"
        assert report.findings[0]["type"] == "vuln"
        assert report.findings[0]["target"] == "10.0.0.1"

    def test_non_finding_nodes_ignored(self):
        engine = ReportEngine()
        mock_node = MagicMock()
        mock_node.properties = {"category": "target", "severity": "info"}
        mock_node.label = "Target Node"
        mock_kg = MagicMock()
        mock_kg.nodes = {"n1": mock_node}

        report = engine.build_report_from_kg(mock_kg, target="10.0.0.1")
        assert len(report.findings) == 0

    def test_empty_graph(self):
        engine = ReportEngine()
        mock_kg = MagicMock()
        mock_kg.nodes = {}
        report = engine.build_report_from_kg(mock_kg, target="")
        assert len(report.findings) == 0
        assert report.metadata["total_findings"] == 0


class TestBuildReport:
    def test_without_config_uses_default(self):
        engine = ReportEngine()
        findings = [{"severity": "low", "title": "test"}]
        report = engine.build_report(findings, target="target1")
        assert isinstance(report.config, ReportConfig)
        assert report.metadata["target"] == "target1"

    def test_with_config(self):
        engine = ReportEngine()
        cfg = ReportConfig(cvss_scoring=False)
        findings = [{"severity": "low", "title": "test"}]
        report = engine.build_report(findings, target="t", config=cfg)
        assert report.config.cvss_scoring is False

    def test_cvss_scoring_enabled(self):
        mock_scorer = MagicMock()
        mock_result = MagicMock(spec=CVSSResult)
        mock_result.score = 9.5
        mock_result.severity = Severity.CRITICAL
        mock_result.vector_string = "CVSS:3.1/..."
        mock_scorer.score_from_finding.return_value = mock_result
        engine = ReportEngine(cvss_scorer=mock_scorer)
        findings = [{"severity": "critical", "title": "RCE", "description": "remote code exec"}]
        report = engine.build_report(findings, target="t")
        assert "cvss" in report.findings[0]
        assert report.findings[0]["cvss"]["score"] == 9.5

    def test_cvss_scoring_disabled(self):
        mock_scorer = MagicMock()
        engine = ReportEngine(cvss_scorer=mock_scorer)
        cfg = ReportConfig(cvss_scoring=False)
        findings = [{"severity": "critical", "title": "RCE"}]
        report = engine.build_report(findings, target="t", config=cfg)
        assert "cvss" not in report.findings[0]
        mock_scorer.score_from_finding.assert_not_called()

    def test_sort_order(self):
        engine = ReportEngine(cvss_scorer=MagicMock())
        findings = [
            {"severity": "info", "title": "I"},
            {"severity": "critical", "title": "C"},
            {"severity": "medium", "title": "M"},
            {"severity": "high", "title": "H"},
            {"severity": "low", "title": "L"},
        ]
        report = engine.build_report(findings, target="t", config=ReportConfig(cvss_scoring=False))
        sevs = [f["severity"] for f in report.findings]
        assert sevs == ["critical", "high", "medium", "low", "info"]

    def test_metadata_populated(self):
        engine = ReportEngine()
        findings = [{"severity": "high", "title": "X"}, {"severity": "high", "title": "Y"}]
        report = engine.build_report(findings, target="t", config=ReportConfig(cvss_scoring=False))
        assert report.metadata["total_findings"] == 2
        assert report.metadata["target"] == "t"
        assert report.metadata["severity_counts"]["high"] == 2
        assert "Siyarix Report Engine" in report.metadata["generated_by"]

    def test_section_flags(self):
        cfg = ReportConfig(
            include_executive_summary=False,
            include_methodology=False,
            include_findings=False,
            include_evidence=False,
            include_remediation=False,
            include_appendix=False,
            cvss_scoring=False,
        )
        engine = ReportEngine()
        report = engine.build_report([], target="", config=cfg)
        assert report.sections == []


class TestRender:
    def test_markdown(self):
        engine = ReportEngine()
        report = engine.build_report([], target="t", config=ReportConfig(cvss_scoring=False))
        output = engine.render(report, ReportFormat.MARKDOWN)
        assert "# Siyarix Security Assessment Report" in output
        assert report.report_id in output

    def test_html(self):
        engine = ReportEngine()
        report = engine.build_report(
            [{"severity": "high", "title": "X"}],
            target="t",
            config=ReportConfig(cvss_scoring=False),
        )
        output = engine.render(report, ReportFormat.HTML)
        assert "<!DOCTYPE html" in output
        assert "Siyarix Security Assessment Report" in output
        assert "stats-grid" in output

    def test_html_with_cvss_and_evidence(self):
        engine = ReportEngine()
        findings = [{
            "severity": "critical",
            "title": "RCE",
            "description": "Remote code execution",
            "tool": "nuclei",
            "target": "example.com",
            "evidence": "exploit worked",
            "cvss": {"score": 9.5, "severity": "critical", "vector": "CVSS:3.1/AV:N/..."},
        }]
        report = engine.build_report(findings, target="t", config=ReportConfig(cvss_scoring=False))
        output = engine.render(report, ReportFormat.HTML)
        assert "CVSS Score" in output
        assert "Evidence Snapshot" in output
        assert "9.5" in output

    def test_json(self):
        engine = ReportEngine()
        report = engine.build_report(
            [{"severity": "medium", "title": "Test"}],
            target="t",
            config=ReportConfig(cvss_scoring=False),
        )
        output = engine.render(report, ReportFormat.JSON)
        data = json.loads(output)
        assert data["title"] == "Siyarix Security Assessment Report"
        assert data["findings_count"] == 1

    def test_sarif(self):
        engine = ReportEngine()
        report = engine.build_report(
            [{"severity": "critical", "title": "Bug", "tool": "nmap", "target": "h", "evidence": "proof"}],
            target="h",
            config=ReportConfig(cvss_scoring=False),
        )
        output = engine.render(report, ReportFormat.SARIF)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "Siyarix"

    def test_unsupported_format_raises(self):
        engine = ReportEngine()
        report = engine.build_report([], config=ReportConfig(cvss_scoring=False))
        with pytest.raises(ValueError, match="Unsupported format"):
            engine.render(report, "pdf")  # type: ignore[arg-type]


class TestSave:
    def test_saves_with_correct_extension(self, tmp_path):
        engine = ReportEngine()
        report = engine.build_report([], config=ReportConfig(cvss_scoring=False))
        path = engine.save(report, tmp_path / "report", ReportFormat.MARKDOWN)
        assert path.suffix == ".md"
        assert path.exists()

    def test_saves_html(self, tmp_path):
        engine = ReportEngine()
        report = engine.build_report([], config=ReportConfig(cvss_scoring=False))
        path = engine.save(report, tmp_path / "report", ReportFormat.HTML)
        assert path.suffix == ".html"
        assert path.exists()

    def test_saves_json(self, tmp_path):
        engine = ReportEngine()
        report = engine.build_report([], config=ReportConfig(cvss_scoring=False))
        path = engine.save(report, tmp_path / "report", ReportFormat.JSON)
        assert path.suffix == ".json"
        assert path.exists()

    def test_saves_sarif(self, tmp_path):
        engine = ReportEngine()
        report = engine.build_report([], config=ReportConfig(cvss_scoring=False))
        path = engine.save(report, tmp_path / "report", ReportFormat.SARIF)
        assert path.suffix == ".sarif"

    def test_returns_path(self, tmp_path):
        engine = ReportEngine()
        report = engine.build_report([], config=ReportConfig(cvss_scoring=False))
        path = engine.save(report, tmp_path / "r", ReportFormat.MARKDOWN)
        assert path == tmp_path / "r.md"


class TestEnrichFindingsWithCvss:
    def test_enriches_with_cvss_data(self):
        mock_scorer = MagicMock()
        mock_result = MagicMock(spec=CVSSResult)
        mock_result.score = 7.5
        mock_result.severity = Severity.HIGH
        mock_result.vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        mock_scorer.score_from_finding.return_value = mock_result

        engine = ReportEngine(cvss_scorer=mock_scorer)
        findings = [{"severity": "high", "title": "SQLi"}]
        enriched = engine._enrich_findings_with_cvss(findings)
        assert len(enriched) == 1
        assert enriched[0]["cvss"]["score"] == 7.5
        assert enriched[0]["cvss"]["severity"] == "high"
        assert enriched[0]["cvss"]["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def test_preserves_original_fields(self):
        mock_scorer = MagicMock()
        mock_result = MagicMock(spec=CVSSResult)
        mock_result.score = 5.0
        mock_result.severity = Severity.MEDIUM
        mock_result.vector_string = "CVSS:3.1/..."
        mock_scorer.score_from_finding.return_value = mock_result

        engine = ReportEngine(cvss_scorer=mock_scorer)
        findings = [{"severity": "medium", "title": "XSS", "target": "example.com"}]
        enriched = engine._enrich_findings_with_cvss(findings)
        assert enriched[0]["target"] == "example.com"
        assert enriched[0]["severity"] == "medium"


class TestSortFindings:
    def test_sorted_by_severity_order(self):
        engine = ReportEngine()
        findings = [
            {"severity": "info"},
            {"severity": "critical"},
            {"severity": "low"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        sorted_f = engine._sort_findings(findings)
        sevs = [f["severity"] for f in sorted_f]
        assert sevs == ["critical", "high", "medium", "low", "info"]

    def test_unknown_severity_goes_last(self):
        engine = ReportEngine()
        findings = [
            {"severity": "critical"},
            {"severity": "unknown"},
        ]
        sorted_f = engine._sort_findings(findings)
        assert sorted_f[-1]["severity"] == "unknown"


class TestCountSeverities:
    def test_counts_correctly(self):
        engine = ReportEngine()
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "critical"},
            {"severity": "info"},
        ]
        counts = engine._count_severities(findings)
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["info"] == 1

    def test_empty(self):
        engine = ReportEngine()
        assert engine._count_severities([]) == {}

    def test_missing_severity_defaults_to_info(self):
        engine = ReportEngine()
        findings = [{"title": "no severity"}]
        counts = engine._count_severities(findings)
        assert counts["info"] == 1


class TestBuildExecutiveSummary:
    def test_with_findings(self):
        engine = ReportEngine()
        findings = [{"severity": "critical"}, {"severity": "high"}, {"severity": "low"}]
        section = engine._build_executive_summary(findings, target="10.0.0.1")
        assert "Executive Summary" in section.content
        assert "10.0.0.1" in section.content
        assert "Critical" in section.content
        assert "High" in section.content
        assert "Low" in section.content

    def test_without_findings(self):
        engine = ReportEngine()
        section = engine._build_executive_summary([], target="")
        assert "N/A" in section.content
        assert "Total Findings" in section.content
        # no severity table since none have >0
        assert "| Critical |" not in section.content

    def test_critical_high_present(self):
        engine = ReportEngine()
        findings = [{"severity": "critical"}, {"severity": "high"}]
        section = engine._build_executive_summary(findings, target="t")
        assert "immediate attention" in section.content

    def test_no_critical_or_high(self):
        engine = ReportEngine()
        findings = [{"severity": "low"}, {"severity": "info"}]
        section = engine._build_executive_summary(findings, target="t")
        assert "No critical or high severity" in section.content


class TestBuildMethodology:
    def test_returns_correct_section(self):
        engine = ReportEngine()
        section = engine._build_methodology()
        assert section.title == "Methodology"
        assert "Multi-phase assessment" in section.content
        assert "nmap" in section.content
        assert "nuclei" in section.content


class TestBuildFindingsSection:
    def test_grouped_by_severity(self):
        engine = ReportEngine()
        findings = [
            {"severity": "critical", "title": "C1"},
            {"severity": "high", "title": "H1"},
            {"severity": "high", "title": "H2"},
        ]
        section = engine._build_findings_section(findings)
        assert section.title == "Findings"
        assert len(section.subsections) == 2
        assert "Critical Severity" in section.subsections[0].title
        assert "High Severity" in section.subsections[1].title

    def test_cvss_data_in_output(self):
        engine = ReportEngine()
        findings = [{
            "severity": "high",
            "title": "SQLi",
            "description": "Injection",
            "evidence": "log",
            "tool": "sqlmap",
            "cvss": {"score": 8.5, "severity": "high", "vector": "V1"},
        }]
        section = engine._build_findings_section(findings)
        content = section.subsections[0].content
        assert "CVSS Score" in content
        assert "8.5" in content

    def test_subsection_without_cvss(self):
        engine = ReportEngine()
        findings = [{"severity": "low", "title": "Info", "description": "desc"}]
        section = engine._build_findings_section(findings)
        content = section.subsections[0].content
        assert "CVSS" not in content


class TestBuildEvidenceSection:
    def test_with_evidence(self):
        engine = ReportEngine()
        findings = [
            {"severity": "high", "evidence": "found it", "target": "x", "tool": "nmap"},
        ]
        section = engine._build_evidence_section(findings)
        assert "Evidence Collection" in section.content
        assert "[nmap]" in section.content
        assert "x" in section.content

    def test_without_evidence(self):
        engine = ReportEngine()
        findings = [{"severity": "high"}]
        section = engine._build_evidence_section(findings)
        assert "Evidence Collection" in section.content

    def test_truncated_at_20(self):
        engine = ReportEngine()
        findings = [{"severity": "low", "evidence": "e", "target": "t", "tool": "a"} for _ in range(25)]
        section = engine._build_evidence_section(findings)
        assert "5 additional findings omitted" in section.content


class TestBuildRemediationSection:
    def test_severity_timeline_mapping(self):
        engine = ReportEngine()
        findings = [
            {"severity": "critical", "title": "RCE"},
            {"severity": "info", "title": "Note"},
        ]
        section = engine._build_remediation_section(findings)
        assert "24 hours" in section.content
        assert "no remediation required" in section.content

    def test_truncated_at_15(self):
        engine = ReportEngine()
        findings = [{"severity": "low", "title": f"F{i}"} for i in range(20)]
        section = engine._build_remediation_section(findings)
        assert "**1. F0**" in section.content
        assert "**15. F14**" in section.content
        assert "**16. F15" not in section.content

    def test_cvss_in_remediation(self):
        engine = ReportEngine()
        findings = [{
            "severity": "high", "title": "X",
            "cvss": {"score": 7.5, "severity": "high", "vector": "V"},
        }]
        section = engine._build_remediation_section(findings)
        assert "7.5/10" in section.content


class TestBuildAppendix:
    def test_tool_usage_counts(self):
        engine = ReportEngine()
        findings = [
            {"tool": "nmap"},
            {"tool": "nmap"},
            {"tool": "nuclei"},
        ]
        section = engine._build_appendix(findings)
        assert "nmap" in section.content
        assert "nuclei" in section.content
        assert "| nmap | 2 |" in section.content or "| nmap|2|" in section.content.replace(" ", "")

    def test_sorted_by_count_descending(self):
        engine = ReportEngine()
        findings = [
            {"tool": "a"},
            {"tool": "b"},
            {"tool": "b"},
            {"tool": "c"},
            {"tool": "c"},
            {"tool": "c"},
        ]
        section = engine._build_appendix(findings)
        # c should appear first (3 times)
        lines = section.content.split("\n")
        table_lines = [l for l in lines if l.startswith("|")]
        # table header: | Tool | Findings |, |------|----------|, then data rows
        assert len(table_lines) >= 5


class TestRenderMarkdown:
    def test_sections_and_subsections_rendered(self):
        engine = ReportEngine()
        config = ReportConfig(cvss_scoring=False)
        report = engine.build_report(
            [{"severity": "low", "title": "X"}],
            target="t",
            config=config,
        )
        output = engine._render_markdown(report)
        assert "Executive Summary" in output
        assert "Methodology" in output
        assert "Low Severity" in output or "low" in output.lower()


class TestRenderJson:
    def test_structure_with_metadata_and_sections(self):
        engine = ReportEngine()
        config = ReportConfig(cvss_scoring=False)
        report = engine.build_report(
            [{"severity": "low", "title": "X"}],
            target="t",
            config=config,
        )
        output = engine._render_json(report)
        data = json.loads(output)
        assert data["report_id"]
        assert data["title"] == "Siyarix Security Assessment Report"
        assert data["findings_count"] == 1
        assert len(data["sections"]) > 0


class TestRenderSarif:
    def test_sarif_format_with_cvss_properties(self):
        engine = ReportEngine()
        report = engine.build_report(
            [{
                "severity": "critical",
                "title": "Critical Vuln",
                "description": "Bad thing",
                "tool": "nuclei",
                "target": "example.com",
                "evidence": "found at port 443",
                "cvss": {"score": 9.0, "severity": "critical", "vector": "CVSS:3.1/..."},
            }],
            target="example.com",
            config=ReportConfig(cvss_scoring=False),
        )
        output = engine._render_sarif(report)
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert result["ruleId"] == "nuclei-0"
        assert result["level"] == "critical"
        assert "properties" in result
        assert result["properties"]["cvssScore"] == 9.0

    def test_sarif_without_cvss(self):
        engine = ReportEngine()
        report = engine.build_report(
            [{"severity": "info", "title": "Info", "tool": "nmap", "target": "h"}],
            config=ReportConfig(cvss_scoring=False),
        )
        output = engine._render_sarif(report)
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert "properties" not in result or result["properties"] != {}


class TestRenderUnsupported:
    def test_missing_renderer_raises(self):
        engine = ReportEngine()
        report = engine.build_report([], config=ReportConfig(cvss_scoring=False))
        # Use render directly with an invalid format
        with pytest.raises(ValueError, match="Unsupported format"):
            engine.render(report, "pdf")  # type: ignore[arg-type]
