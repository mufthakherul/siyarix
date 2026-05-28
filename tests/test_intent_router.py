# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.core.intent_router import IntentRouter, RiskTier


def test_intent_router_high_risk_for_exploit() -> None:
    router = IntentRouter()
    route = router.route(
        "exploit target.com using metasploit", preferred_mode="integrated"
    )
    assert route.risk_tier == RiskTier.HIGH
    assert route.requires_confirmation is True


def test_intent_router_unknown_promotes_registry_to_integrated() -> None:
    router = IntentRouter()
    route = router.route("do something magical unknown", preferred_mode="registry")
    assert route.mode == "integrated"
