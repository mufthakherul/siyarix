# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.compat import IntentRouter, RiskTier


def test_intent_router_high_risk_for_exploit() -> None:
    router = IntentRouter()
    route = router.route("exploit target.com using metasploit", preferred_mode="integrated")
    assert route.mode == "exploit"
    assert route.risk_tier.value == RiskTier.HIGH
    assert route.requires_confirmation is True


def test_intent_router_scan() -> None:
    router = IntentRouter()
    route = router.route("run a port scan with nmap")
    assert route.mode == "scan"
    assert route.risk_tier.value == RiskTier.MEDIUM
    assert route.requires_confirmation is False


def test_intent_router_recon() -> None:
    router = IntentRouter()
    route = router.route("discover subdomains")
    assert route.mode == "recon"
    assert route.risk_tier.value == RiskTier.LOW
    assert route.requires_confirmation is False


def test_intent_router_web() -> None:
    router = IntentRouter()
    route = router.route("run nuclei on http://example.com")
    assert route.mode == "web"
    assert route.risk_tier.value == RiskTier.MEDIUM
    assert route.requires_confirmation is False


def test_intent_router_brute() -> None:
    router = IntentRouter()
    route = router.route("brute force the ftp server password")
    assert route.mode == "brute"
    assert route.risk_tier.value == RiskTier.HIGH
    assert route.requires_confirmation is True


def test_intent_router_unknown_promotes_registry_to_integrated() -> None:
    router = IntentRouter()
    route = router.route("do something magical unknown", preferred_mode="registry")
    assert route.mode == "general"
    assert route.risk_tier.value == RiskTier.LOW
