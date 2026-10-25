# SPDX-License-Identifier: AGPL-3.0-or-later

"""SX-005: HTML reports must not execute injected finding/metadata markup."""

from __future__ import annotations

from siyarix.report import ReportEngine, ReportFormat
from siyarix.report.models import ReportConfig


def test_html_report_escapes_script_payloads() -> None:
    eng = ReportEngine()
    payload = "<img src=x onerror=document.title='AUDIT_XSS_CONFIRMED'>"
    report = eng.build_report(
        [
            {
                "title": payload,
                "description": payload,
                "severity": "high",
                "tool": "audit",
                "target": payload,
                "evidence": payload,
            }
        ],
        target=payload,
        config=ReportConfig(title="XSS Probe", cvss_scoring=False),
    )
    html = eng.render(report, ReportFormat.HTML)
    assert "Content-Security-Policy" in html
    assert "<img src=x onerror=" not in html
    assert "AUDIT_XSS_CONFIRMED" in html  # still visible as escaped text
    assert "badge-high" in html


def test_html_report_uses_contrasting_severity_badges() -> None:
    eng = ReportEngine()
    report = eng.build_report(
        [{"title": "m", "description": "d", "severity": "medium", "tool": "t", "target": "x"}],
        config=ReportConfig(title="Badge", cvss_scoring=False),
    )
    html = eng.render(report, ReportFormat.HTML)
    assert "badge-medium" in html
    assert "--med-fg" in html or "badge-medium" in html


def test_html_report_defaults_offline_without_cdn_fonts() -> None:
    eng = ReportEngine()
    report = eng.build_report(
        [{"title": "m", "description": "d", "severity": "info", "tool": "t", "target": "x"}],
        config=ReportConfig(title="Offline", cvss_scoring=False),
    )
    html = eng.render(report, ReportFormat.HTML)
    assert "fonts.googleapis.com" not in html
    assert "system-ui" in html


def test_html_report_online_fonts_expand_csp() -> None:
    eng = ReportEngine()
    report = eng.build_report(
        [{"title": "m", "description": "d", "severity": "info", "tool": "t", "target": "x"}],
        config=ReportConfig(title="Online", cvss_scoring=False, offline=False),
    )
    html = eng.render(report, ReportFormat.HTML)
    assert "fonts.googleapis.com" in html
    assert "fonts.gstatic.com" in html
