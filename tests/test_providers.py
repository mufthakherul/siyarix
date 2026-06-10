# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.providers import ProviderManager, ProviderProfile


def test_provider_manager_profiles():
    pm = ProviderManager()
    profiles = pm.list_profiles()
    assert len(profiles) >= 4
    names = [p.name for p in profiles]
    assert "openai" in names
    assert "anthropic" in names
    assert "gemini" in names


def test_provider_select():
    pm = ProviderManager()
    provider, model = pm.select_provider()
    assert isinstance(provider, str)
    assert isinstance(model, str)


def test_provider_classify_error():
    pm = ProviderManager()
    from siyarix.providers import FailoverReason

    err = Exception("429 rate limit exceeded")
    result = pm.classify_error("openai", err)
    assert result.reason == FailoverReason.RATE_LIMIT


def test_provider_stats():
    pm = ProviderManager()
    stats = pm.stats()
    assert "total_providers" in stats
    assert stats["total_providers"] >= 4
