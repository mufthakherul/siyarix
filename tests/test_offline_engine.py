# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for OfflineReasoningEngine — local reasoning and planning without LLM."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from siyarix.offline_engine import (
    OfflineReasoningEngine,
)
from siyarix.models import ExecutionPlan


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.search_findings.return_value = [
        {
            "port": 80,
            "service": "http",
            "technology": "nginx",
            "target": "10.0.0.1",
            "severity": "info",
            "title": "Open Port 80",
        },
        {
            "port": 443,
            "service": "https",
            "technology": "nginx",
            "target": "10.0.0.1",
            "severity": "info",
            "title": "Open Port 443",
        },
        {
            "port": 0,
            "service": "",
            "technology": "",
            "target": "10.0.0.1",
            "severity": "critical",
            "title": "SQL Injection in /api/login",
        },
    ]
    store.stats.return_value = {"total_scans": 5, "total_findings": 12}
    return store


def test_resolve_open_ports_query(mock_store):
    engine = OfflineReasoningEngine(offline_store=mock_store)
    res = engine.resolve_query("what ports are open on 10.0.0.1", target="10.0.0.1")
    assert res is not None
    assert "Discovered Open Ports" in res
    assert "80" in res
    assert "443" in res
    assert "nginx" in res


def test_resolve_findings_query(mock_store):
    engine = OfflineReasoningEngine(offline_store=mock_store)
    res = engine.resolve_query("show critical vulnerabilities on 10.0.0.1", target="10.0.0.1")
    assert res is not None
    assert "Vulnerability Findings" in res
    assert "SQL Injection" in res


def test_resolve_remediation_query():
    engine = OfflineReasoningEngine()
    res = engine.resolve_query("how to fix sql injection")
    assert res is not None
    assert "Security Advisory: SQL Injection (SQLi)" in res
    assert "CWE-89" in res
    assert "remediation" in res.lower()
    assert "parameterized" in res.lower()


def test_resolve_remediation_xss():
    engine = OfflineReasoningEngine()
    res = engine.resolve_query("how to mitigate xss")
    assert res is not None
    assert "Cross-Site Scripting" in res
    assert "CWE-79" in res


def test_plan_offline_instruction_port_scan():
    engine = OfflineReasoningEngine()
    plan = engine.plan_offline_instruction("port scan 192.168.1.10", target="192.168.1.10")
    assert isinstance(plan, ExecutionPlan)
    assert len(plan.steps) == 1
    assert "nmap" in plan.steps[0].command
    assert "192.168.1.10" in plan.steps[0].command


def test_plan_offline_instruction_web():
    engine = OfflineReasoningEngine()
    plan = engine.plan_offline_instruction(
        "check http headers on example.com", target="example.com"
    )
    assert isinstance(plan, ExecutionPlan)
    assert len(plan.steps) == 1
    assert "curl" in plan.steps[0].command
    assert "example.com" in plan.steps[0].command
