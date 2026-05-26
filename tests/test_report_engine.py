"""Tests for ReportEngine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phalanx.report_engine import (Report, ReportConfig, ReportEngine,
                                   ReportFormat)

pytestmark = pytest.mark.report


class TestReportEngine:
    @pytest.fixture
    def engine(self):
        return ReportEngine()

    @pytest.fixture
    def sample_findings(self):
        return [
            {
                "title": "RCE in web app",
                "severity": "critical",
                "description": "Remote code execution",
                "evidence": "http://example.com/exploit",
                "tool": "nuclei",
                "target": "example.com",
            },
            {
                "title": "Open SSH port",
                "severity": "low",
                "description": "SSH port 22 open",
                "evidence": "22/tcp",
                "tool": "nmap",
                "target": "example.com",
            },
        ]

    def test_build_report(self, engine, sample_findings):
        report = engine.build_report(sample_findings, target="example.com")
        assert isinstance(report, Report)
        assert len(report.findings) == 2
        assert report.metadata["total_findings"] == 2

    def test_build_report_sorted(self, engine, sample_findings):
        report = engine.build_report(sample_findings)
        assert report.findings[0]["severity"] == "critical"

    def test_render_markdown(self, engine, sample_findings):
        report = engine.build_report(sample_findings)
        md = engine.render(report, ReportFormat.MARKDOWN)
        assert "RCE in web app" in md
        assert "Executive Summary" in md

    def test_render_html(self, engine, sample_findings):
        report = engine.build_report(sample_findings)
        html = engine.render(report, ReportFormat.HTML)
        assert "<h1>" in html
        assert "RCE in web app" in html

    def test_render_json(self, engine, sample_findings):
        report = engine.build_report(sample_findings)
        json_str = engine.render(report, ReportFormat.JSON)
        data = json.loads(json_str)
        assert data["findings_count"] == 2
        assert data["report_id"]

    def test_render_sarif(self, engine, sample_findings):
        report = engine.build_report(sample_findings)
        sarif_str = engine.render(report, ReportFormat.SARIF)
        data = json.loads(sarif_str)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 2

    def test_save_to_file(self, engine, sample_findings, tmp_path: Path):
        report = engine.build_report(sample_findings)
        output = engine.save(report, tmp_path / "report", ReportFormat.MARKDOWN)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "RCE in web app" in content

    def test_executive_summary_structure(self, engine, sample_findings):
        section = engine._build_executive_summary(sample_findings, "example.com")
        assert "Executive Summary" in section.title
        assert "Critical" in section.content

    def test_methodology_section(self, engine):
        section = engine._build_methodology()
        assert "Methodology" in section.title
        assert "CVSS 3.1" in section.content

    def test_empty_findings(self, engine):
        report = engine.build_report([], target="test")
        assert report.metadata["total_findings"] == 0

    def test_report_auto_id(self):
        report = Report()
        assert len(report.report_id) == 16

    def test_report_config_defaults(self):
        cfg = ReportConfig()
        assert cfg.include_executive_summary is True
