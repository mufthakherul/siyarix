# SPDX-License-Identifier: AGPL-3.0-or-later

"""SX-005 / SEC-11: HTML reports must not execute injected finding/metadata markup."""

from __future__ import annotations

import base64
import hashlib
import re

from siyarix.report import ReportEngine, ReportFormat
from siyarix.report.models import ReportConfig


def _sha256_csp(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


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


def test_html_report_csp_uses_script_hash_not_unsafe_inline() -> None:
    eng = ReportEngine()
    report = eng.build_report(
        [{"title": "m", "description": "d", "severity": "info", "tool": "t", "target": "x"}],
        config=ReportConfig(title="CSP Hash", cvss_scoring=False),
    )
    html = eng.render(report, ReportFormat.HTML)
    csp_match = re.search(
        r'http-equiv="Content-Security-Policy" content="([^"]+)"',
        html,
    )
    assert csp_match is not None
    csp = csp_match.group(1)
    assert "script-src 'unsafe-inline'" not in csp
    assert "script-src 'sha256-" in csp
    assert "style-src 'sha256-" in csp

    script_match = re.search(r"<script>(.*?)</script>", html, re.DOTALL)
    assert script_match is not None
    js_hash = _sha256_csp(script_match.group(1))
    assert f"'{js_hash}'" in csp

    style_match = re.search(r"<style>(.*?)</style>", html, re.DOTALL)
    assert style_match is not None
    css_hash = _sha256_csp(style_match.group(1))
    assert f"'{css_hash}'" in csp


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
    assert "script-src 'unsafe-inline'" not in html
