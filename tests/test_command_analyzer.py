# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for CommandAnalyzer — enterprise intent classification, target normalization, and OPSEC rating."""

from __future__ import annotations

import pytest

from siyarix.command_analyzer import (
    CommandAnalyzer,
    CommandIntent,
    OpsecRisk,
)


@pytest.fixture
def analyzer():
    return CommandAnalyzer()


def test_intent_classification(analyzer):
    assert analyzer.analyze("hello there").intent == CommandIntent.CONVERSATIONAL
    assert (
        analyzer.analyze("summarize findings into an executive report").intent
        == CommandIntent.REPORTING
    )
    assert (
        analyzer.analyze("whois and dns lookup on example.com").intent
        == CommandIntent.RECONNAISSANCE
    )
    assert analyzer.analyze("port scan 192.168.1.1").intent == CommandIntent.PORT_SCAN
    assert (
        analyzer.analyze("run nuclei vulnerability scan against target").intent
        == CommandIntent.VULNERABILITY_ASSESSMENT
    )
    assert (
        analyzer.analyze("generate reverse shell payload for linux").intent
        == CommandIntent.EXPLOITATION
    )
    assert (
        analyzer.analyze("audit compliance with cis benchmark").intent
        == CommandIntent.DEFENSIVE_AUDIT
    )


def test_target_extraction(analyzer):
    res1 = analyzer.analyze("scan https://api.example.com:8443/v1/auth")
    assert len(res1.targets) == 1
    t = res1.targets[0]
    assert t.target_type == "url"
    assert t.host == "api.example.com"
    assert t.port == 8443
    assert t.path == "/v1/auth"
    assert res1.primary_target == "https://api.example.com:8443/v1/auth"

    res2 = analyzer.analyze("sweep 10.0.0.0/24 subnet")
    assert len(res2.targets) == 1
    assert res2.targets[0].target_type == "cidr"
    assert res2.primary_target == "10.0.0.0/24"

    res3 = analyzer.analyze("check host 192.168.1.50 and port 80")
    assert len(res3.targets) == 1
    assert res3.targets[0].target_type == "ipv4"
    assert res3.primary_target == "192.168.1.50"


def test_opsec_risk_rating(analyzer):
    res_passive = analyzer.analyze("whois on example.com")
    assert res_passive.opsec_risk == OpsecRisk.PASSIVE
    assert res_passive.risk_score <= 1

    res_intrusive = analyzer.analyze("brute force ssh using hydra on 10.0.0.1")
    assert res_intrusive.opsec_risk == OpsecRisk.INTRUSIVE
    assert res_intrusive.risk_score >= 6
    assert len(res_intrusive.opsec_warnings) > 0

    res_exploit = analyzer.analyze("exploit cve-2024-1234 using metasploit payload")
    assert res_exploit.opsec_risk == OpsecRisk.HIGH_RISK
    assert res_exploit.risk_score >= 8


def test_platform_notes(analyzer):
    res = analyzer.analyze("sudo nmap -sS 10.0.0.1")
    assert res.intent == CommandIntent.PORT_SCAN
