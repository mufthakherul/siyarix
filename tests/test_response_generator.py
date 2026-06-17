# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ResponseGenerator, FindingGroup, SummarySection."""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock

import pytest
from rich.panel import Panel

from siyarix.response import FindingGroup, ResponseGenerator, SummarySection


class TestFindingGroup:
    def test_post_init_sets_count(self):
        g = FindingGroup(severity="high", items=[{"a": 1}, {"b": 2}])
        assert g.count == 2
        assert g.severity == "high"

    def test_post_init_empty_items(self):
        g = FindingGroup(severity="info", items=[])
        assert g.count == 0


class TestSummarySection:
    def test_default_style(self):
        s = SummarySection(title="Test")
        assert s.title == "Test"
        assert s.lines == []
        assert s.style == "white"

    def test_custom_style_and_lines(self):
        s = SummarySection(title="Foo", lines=["a", "b"], style="red")
        assert s.title == "Foo"
        assert s.lines == ["a", "b"]
        assert s.style == "red"


class TestResponseGeneratorConstants:
    def test_severity_order(self):
        assert ResponseGenerator.SEVERITY_ORDER == [
            "critical", "high", "medium", "low", "info",
        ]

    def test_severity_colors(self):
        colors = ResponseGenerator.SEVERITY_COLORS
        assert colors["critical"] == "red"
        assert colors["high"] == "red"
        assert colors["medium"] == "yellow"
        assert colors["low"] == "green"
        assert colors["info"] == "blue"

    def test_severity_icons(self):
        icons = ResponseGenerator.SEVERITY_ICONS
        assert "critical" in icons
        assert "info" in icons


class TestResponseGeneratorInit:
    def test_with_custom_console(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)
        assert rg._console is mock_con

    def test_without_console(self):
        rg = ResponseGenerator()
        assert rg._console is not None


class TestGroupFindings:
    def test_empty(self):
        rg = ResponseGenerator()
        assert rg._group_findings([]) == {}

    def test_single_severity(self):
        rg = ResponseGenerator()
        findings = [
            {"severity": "high", "title": "X"},
            {"severity": "high", "title": "Y"},
        ]
        groups = rg._group_findings(findings)
        assert list(groups.keys()) == ["high"]
        assert groups["high"].count == 2
        assert groups["high"].severity == "high"

    def test_multiple_severities(self):
        rg = ResponseGenerator()
        findings = [
            {"severity": "critical", "title": "A"},
            {"severity": "high", "title": "B"},
            {"severity": "medium", "title": "C"},
            {"severity": "low", "title": "D"},
            {"severity": "info", "title": "E"},
        ]
        groups = rg._group_findings(findings)
        assert set(groups.keys()) == {"critical", "high", "medium", "low", "info"}

    def test_missing_severity_defaults_to_info(self):
        rg = ResponseGenerator()
        findings = [{"title": "no sev"}]
        groups = rg._group_findings(findings)
        assert "info" in groups
        assert groups["info"].count == 1


class TestGenerateInsights:
    def test_critical_count(self):
        rg = ResponseGenerator()
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
        ]
        insights = rg._generate_insights(findings)
        assert any("critical" in i for i in insights)
        assert any("high" in i for i in insights)

    def test_only_high(self):
        rg = ResponseGenerator()
        findings = [{"severity": "high"}, {"severity": "high"}]
        insights = rg._generate_insights(findings)
        assert any("high" in i for i in insights)
        assert not any("critical" in i for i in insights)

    def test_open_ports_with_int_ports(self):
        rg = ResponseGenerator()
        findings = [
            {"port": "80"},
            {"port": "22"},
            {"port": "443"},
        ]
        insights = rg._generate_insights(findings)
        assert any("open ports" in i for i in insights)
        port_lines = [i for i in insights if "open ports" in i]
        assert "80, 22, 443" in port_lines[0] or "22, 80, 443" in port_lines[0]

    def test_open_ports_with_non_int_ports_skipped(self):
        rg = ResponseGenerator()
        findings = [
            {"port": "abc"},
            {"port": "80"},
        ]
        insights = rg._generate_insights(findings)
        port_lines = [i for i in insights if "open ports" in i]
        assert port_lines  # port 80 should show
        assert "1 open ports" in port_lines[0] or "1" in port_lines[0]

    def test_more_than_10_ports_shows_ellipsis(self):
        rg = ResponseGenerator()
        findings = [{"port": str(i)} for i in range(1, 15)]
        insights = rg._generate_insights(findings)
        port_lines = [i for i in insights if "open ports" in i]
        assert port_lines
        assert "..." in port_lines[0]

    def test_empty_findings(self):
        rg = ResponseGenerator()
        insights = rg._generate_insights([])
        assert any("No findings" in i for i in insights)

    def test_ports_sorted_and_deduped(self):
        rg = ResponseGenerator()
        findings = [
            {"port": "443"},
            {"port": "80"},
            {"port": "443"},
            {"port": "22"},
        ]
        insights = rg._generate_insights(findings)
        port_lines = [i for i in insights if "open ports" in i]
        assert port_lines
        assert "22, 80, 443" in port_lines[0]


class TestBuildStats:
    def test_success_partial(self):
        rg = ResponseGenerator()
        s1 = MagicMock(status="completed")
        s2 = MagicMock(status="failed")
        stats = rg._build_stats(True, [s1, s2], [{"a": 1}], 1500.0)
        assert any("Success" in s for s in stats)
        assert any("1/2" in s.replace("[cyan]", "").replace("[/cyan]", "") for s in stats)
        assert any("1" in s and "Findings" in s for s in stats)
        assert any("1.5s" in s.replace("[magenta]", "").replace("[/magenta]", "") for s in stats)

    def test_all_succeeded(self):
        rg = ResponseGenerator()
        s1 = MagicMock(status="completed")
        s2 = MagicMock(status="completed")
        stats = rg._build_stats(True, [s1, s2], [], 500.0)
        assert any("Success" in s for s in stats)
        assert any("2/2" in s.replace("[cyan]", "").replace("[/cyan]", "") for s in stats)

    def test_all_failed(self):
        rg = ResponseGenerator()
        s1 = MagicMock(status="failed")
        stats = rg._build_stats(False, [s1], [], 250.0)
        assert any("Partial" in s for s in stats)

    def test_status_with_value_attr(self):
        rg = ResponseGenerator()
        mock_status = MagicMock()
        mock_status.value = "completed"
        s1 = MagicMock(status=mock_status)
        stats = rg._build_stats(True, [s1], [], 0)
        assert any("1/1" in s.replace("[cyan]", "").replace("[/cyan]", "") for s in stats)


class TestRenderResults:
    def test_successful_render(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        step = MagicMock()
        step.status = "completed"
        step.step_id = "step_1"
        step.output = "done"

        rg.render_results(
            success=True,
            summary="All good",
            findings=[{"severity": "low", "title": "Minor issue", "target": "host1"}],
            step_results=[step],
            duration_ms=1000.0,
            goal="test goal",
        )

        assert mock_con.print.call_count >= 2

    def test_render_with_partial_failure_and_insights(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        step_s = MagicMock(status="completed", step_id="s1", output="ok")
        step_f = MagicMock(status="failed", step_id="s2", output="err")

        rg.render_results(
            success=False,
            summary="Partial",
            findings=[{"severity": "critical", "title": "Bad", "port": "8080", "host": "t"}],
            step_results=[step_s, step_f],
            duration_ms=2000.0,
            goal="scan",
        )

        assert mock_con.print.call_count >= 2

    def test_render_with_more_than_12_findings_truncates(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        findings = []
        for i in range(15):
            findings.append({"severity": "medium", "title": f"F{i}", "target": "h"})

        step = MagicMock(status="completed", step_id="s1", output="ok")

        rg.render_results(
            success=True,
            summary="Done",
            findings=findings,
            step_results=[step],
            duration_ms=500.0,
            goal="g",
        )

        assert mock_con.print.call_count >= 2
        all_renderables = []
        for call in mock_con.print.call_args_list:
            args, _ = call
            if args and hasattr(args[0], "renderable"):
                all_renderables.append(args[0].renderable)
        assert any("more" in str(t) for t in all_renderables)

    def test_finding_without_target_or_port(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        step = MagicMock(status="completed", step_id="s1", output="ok")
        rg.render_results(
            success=True,
            summary="test",
            findings=[{"severity": "info", "title": "Bare finding"}],
            step_results=[step],
            duration_ms=100.0,
            goal="g",
        )
        assert mock_con.print.call_count >= 2

    def test_empty_findings_and_steps(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        rg.render_results(
            success=True,
            summary="Nothing to do",
            findings=[],
            step_results=[],
            duration_ms=0.0,
            goal="empty",
        )

        assert mock_con.print.call_count == 3  # exec summary + insights + stats bar


class TestRenderPlan:
    def test_with_command(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        step = MagicMock()
        step.tool = "nmap"
        step.description = "Scan ports"
        step.command = "nmap -sV target"

        rg.render_plan([step])
        assert mock_con.print.called

    def test_with_description_only(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        step = MagicMock()
        step.tool = "nmap"
        step.description = "Scan ports"
        step.command = ""

        rg.render_plan([step])
        assert mock_con.print.called

    def test_no_tool_no_desc_no_command(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        step = MagicMock()
        step.tool = ""
        step.description = ""
        step.command = ""

        rg.render_plan([step])
        assert mock_con.print.called

    def test_empty_steps(self):
        mock_con = MagicMock()
        rg = ResponseGenerator(console=mock_con)

        rg.render_plan([])
        mock_con.print.assert_not_called()
