from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exhaustive tests for siyarix.model_aliases — covers normalize_model_id,
resolve_alias, list_aliases, register_alias, and all branches/edge cases."""


import copy
from typing import Any

import pytest

from siyarix.model_aliases import (
    _PROVIDER_ALIASES,
    list_aliases,
    normalize_model_id,
    register_alias,
    resolve_alias,
)


# ── Fixture: preserve global state ───────────────────────────────────────

@pytest.fixture(autouse=True)
def _preserve_aliases() -> Any:
    saved = copy.deepcopy(_PROVIDER_ALIASES)
    yield
    _PROVIDER_ALIASES.clear()
    _PROVIDER_ALIASES.update(saved)


# ── normalize_model_id ───────────────────────────────────────────────────

class TestNormalizeModelId:
    def test_empty_model_id_returns_empty(self) -> None:
        assert normalize_model_id("anthropic", "") == ""

    def test_none_model_id_returns_none(self) -> None:
        assert normalize_model_id("anthropic", None) is None  # type: ignore[arg-type]

    def test_provider_none_does_not_crash(self) -> None:
        result = normalize_model_id(None, "opus")
        assert result == "opus"

    def test_provider_case_insensitive(self) -> None:
        result = normalize_model_id("ANTHROPIC", "opus")
        assert result == "claude-opus-4-8"

    def test_exact_alias_anthropic_opus(self) -> None:
        assert normalize_model_id("anthropic", "opus") == "claude-opus-4-8"

    def test_exact_alias_anthropic_sonnet(self) -> None:
        assert normalize_model_id("anthropic", "sonnet") == "claude-sonnet-4-6"

    def test_exact_alias_anthropic_haiku(self) -> None:
        assert normalize_model_id("anthropic", "haiku") == "claude-haiku-4-5"

    def test_exact_alias_gemini_3_pro(self) -> None:
        result = normalize_model_id("gemini", "gemini-3-pro")
        assert result == "gemini-3.1-pro-preview"

    def test_exact_alias_gemini_3_flash(self) -> None:
        result = normalize_model_id("gemini", "gemini-3-flash")
        assert result == "gemini-3-flash-preview"

    def test_exact_alias_xai(self) -> None:
        result = normalize_model_id("xai", "grok-4-fast-reasoning")
        assert result == "grok-4-fast"

    def test_exact_alias_together(self) -> None:
        result = normalize_model_id("together", "moonshotai/Kimi-K2.5")
        assert result == "moonshotai/Kimi-K2.6"

    def test_exact_alias_deepseek(self) -> None:
        result = normalize_model_id("deepseek", "deepseek-v4")
        assert result == "deepseek-v4-flash"

    def test_exact_alias_openrouter(self) -> None:
        result = normalize_model_id("openrouter", "openai/gpt-5.4")
        assert result == "openai/gpt-5.4"

    def test_exact_alias_zai(self) -> None:
        result = normalize_model_id("zai", "glm-5")
        assert result == "glm-5.1"

    def test_exact_alias_minimax(self) -> None:
        result = normalize_model_id("minimax", "MiniMax-M3")
        assert result == "MiniMax-M3"

    def test_no_match_returns_original(self) -> None:
        result = normalize_model_id("anthropic", "claude-opus-5")
        assert result == "claude-opus-5"

    def test_unknown_provider_returns_original(self) -> None:
        result = normalize_model_id("unknown_provider", "opus")
        assert result == "opus"

    def test_anthropic_dot_to_dash_opus(self) -> None:
        result = normalize_model_id("anthropic", "claude-opus-4.8")
        assert result == "claude-opus-4-8"

    def test_anthropic_dot_to_dash_sonnet(self) -> None:
        result = normalize_model_id("anthropic", "claude-sonnet-4.6")
        assert result == "claude-sonnet-4-6"

    def test_anthropic_dot_to_dash_haiku(self) -> None:
        result = normalize_model_id("anthropic", "claude-haiku-4.5")
        assert result == "claude-haiku-4-5"

    def test_anthropic_dot_short_form(self) -> None:
        result = normalize_model_id("anthropic", "opus-4.8")
        assert result.startswith("claude-")
        assert "4-8" in result

    def test_anthropic_openrouter_prefix_unchanged(self) -> None:
        result = normalize_model_id("openrouter", "anthropic/claude-opus-4.8")
        assert result == "anthropic/claude-opus-4.8"

    def test_anthropic_vercel_gateway_dot_to_dash(self) -> None:
        result = normalize_model_id("vercel-ai-gateway", "claude-sonnet-4.6")
        assert result == "claude-sonnet-4-6"

    def test_xai_dot_to_dash_via_exact_alias(self) -> None:
        result = normalize_model_id("xai", "grok-4.20-reasoning")
        assert result == "grok-4.20-beta-latest-reasoning"

    def test_xai_dot_to_dash_no_suffix(self) -> None:
        result = normalize_model_id("xai", "grok-4.20")
        assert result == "grok-4-20"

    def test_xai_dot_to_dash_fast(self) -> None:
        result = normalize_model_id("xai", "grok-4-fast")
        assert result == "grok-4-fast"

    def test_xai_dot_to_dash_build_suffix(self) -> None:
        result = normalize_model_id("xai", "grok-4.20-build")
        assert result == "grok-4-20-build"

    def test_partial_match_no_dot_not_rewritten(self) -> None:
        result = normalize_model_id("xai", "grok47")
        assert result == "grok47"

    def test_gemini_preview_regex_no_change(self) -> None:
        result = normalize_model_id("gemini", "gemini-2.0-pro")
        assert result == "gemini-2.0-pro"

    def test_gemini_unknown_variant_unaffected(self) -> None:
        result = normalize_model_id("gemini", "gemini-3.0-pro")
        assert result == "gemini-3.0-pro"

    def test_azure_exact_alias(self) -> None:
        result = normalize_model_id("azure", "gpt-5.4")
        assert result == "gpt-5.4"

    def test_azure_unknown_returns_original(self) -> None:
        result = normalize_model_id("azure", "gpt-5")
        assert result == "gpt-5"

    def test_provider_strips_whitespace(self) -> None:
        result = normalize_model_id("  anthropic  ", "opus")
        assert result == "claude-opus-4-8"


# ── resolve_alias ────────────────────────────────────────────────────────

class TestResolveAlias:
    def test_known_alias(self) -> None:
        result = resolve_alias("anthropic", "opus")
        assert result == "claude-opus-4-8"

    def test_unknown_alias_returns_original(self) -> None:
        result = resolve_alias("anthropic", "nonexistent")
        assert result == "nonexistent"

    def test_unknown_provider_returns_original(self) -> None:
        result = resolve_alias("nope", "opus")
        assert result == "opus"

    def test_provider_none_returns_original(self) -> None:
        result = resolve_alias(None, "something")
        assert result == "something"

    def case_insensitive_provider(self) -> None:
        result = resolve_alias("GEMINI", "gemini-3-pro")
        assert result == "gemini-3.1-pro-preview"

    def test_empty_alias(self) -> None:
        result = resolve_alias("anthropic", "")
        assert result == ""


# ── list_aliases ─────────────────────────────────────────────────────────

class TestListAliases:
    def test_all_aliases_returns_copy(self) -> None:
        all_aliases = list_aliases()
        assert all_aliases == _PROVIDER_ALIASES
        assert all_aliases is not _PROVIDER_ALIASES

    def test_filter_by_provider(self) -> None:
        result = list_aliases("anthropic")
        assert "anthropic" in result
        assert len(result) == 1
        assert result["anthropic"] == _PROVIDER_ALIASES["anthropic"]

    def test_unknown_provider_returns_empty(self) -> None:
        result = list_aliases("nonexistent")
        assert result == {"nonexistent": {}}

    def test_provider_case_insensitive(self) -> None:
        result = list_aliases("ANTHROPIC")
        assert "anthropic" in result

    def test_provider_strips_whitespace(self) -> None:
        result = list_aliases("  gemini  ")
        assert "gemini" in result


# ── register_alias ───────────────────────────────────────────────────────

class TestRegisterAlias:
    def test_new_provider(self) -> None:
        register_alias("custom_provider", "my-model", "real-model-v2")
        assert _PROVIDER_ALIASES["custom_provider"]["my-model"] == "real-model-v2"

    def test_add_to_existing_provider(self) -> None:
        register_alias("anthropic", "new-alias", "claude-opus-5")
        assert _PROVIDER_ALIASES["anthropic"]["new-alias"] == "claude-opus-5"

    def test_overwrites_existing_alias(self) -> None:
        register_alias("anthropic", "opus", "claude-opus-5")
        assert _PROVIDER_ALIASES["anthropic"]["opus"] == "claude-opus-5"

    def test_provider_normalized_lowercase(self) -> None:
        register_alias("CUSTOM_PROVIDER", "a", "b")
        assert "custom_provider" in _PROVIDER_ALIASES

    def test_affects_normalize_model_id(self) -> None:
        register_alias("test_prov", "short", "full-version")
        result = normalize_model_id("test_prov", "short")
        assert result == "full-version"

    def test_affects_resolve_alias(self) -> None:
        register_alias("test_prov", "short", "full-version")
        result = resolve_alias("test_prov", "short")
        assert result == "full-version"

    def test_affects_list_aliases(self) -> None:
        register_alias("test_prov", "short", "full-version")
        result = list_aliases("test_prov")
        assert result["test_prov"]["short"] == "full-version"



"""Final coverage tests for siyarix.model_aliases — targets remaining uncovered lines and edge cases."""


import copy
from typing import Any

import pytest

from siyarix.model_aliases import (
    _PROVIDER_ALIASES,
    list_aliases,
    normalize_model_id,
    register_alias,
    resolve_alias,
)


@pytest.fixture(autouse=True)
def _preserve_aliases() -> Any:
    saved = copy.deepcopy(_PROVIDER_ALIASES)
    yield
    _PROVIDER_ALIASES.clear()
    _PROVIDER_ALIASES.update(saved)


class TestNormalizeModelIdRemainingBranches:
    """Covers the last uncovered lines: Google preview path (lines 82-84), edge cases."""

    def test_gemini_3_dot_0_pro_enters_block(self) -> None:
        """Cover the 'if int(major) >= 3:' branch (line 82) and inner pass (line 84)."""
        result = normalize_model_id("gemini", "gemini-3.0-pro")
        assert result == "gemini-3.0-pro"

    def test_gemini_3_dot_0_no_variant(self) -> None:
        """Cover variant being None (inner expression eval to False)."""
        result = normalize_model_id("gemini", "gemini-3.0")
        assert result == "gemini-3.0"

    def test_gemini_4_dot_0_pro(self) -> None:
        """Cover major > 3 variant."""
        result = normalize_model_id("gemini", "gemini-4.0-pro")
        assert result == "gemini-4.0-pro"

    def test_gemini_4_dot_0_flash_lite(self) -> None:
        """Cover flash-lite variant."""
        result = normalize_model_id("gemini", "gemini-4.0-flash-lite")
        assert result == "gemini-4.0-flash-lite"

    def test_gemini_major_2_no_match(self) -> None:
        """Cover int(major) < 3 branch (line 82 False)."""
        result = normalize_model_id("gemini", "gemini-2.0-pro")
        assert result == "gemini-2.0-pro"

    def test_register_alias_creates_new_provider_dict(self) -> None:
        """Cover lines 131-133 in register_alias for new provider."""
        register_alias("my_custom_provider", "my-model", "my-model-v2")
        assert "my_custom_provider" in _PROVIDER_ALIASES
        assert _PROVIDER_ALIASES["my_custom_provider"]["my-model"] == "my-model-v2"

    def test_resolve_alias_provider_none_missing(self) -> None:
        """resolve_alias with no provider and alias not in any list."""
        result = resolve_alias(None, "nonexistent")
        assert result == "nonexistent"

    def test_normalize_model_id_unknown_provider_returns_original(self) -> None:
        """Cover provider not in _PROVIDER_ALIASES and not gemini/anthropic/xai."""
        result = normalize_model_id("nonexistent_provider", "some-model")
        assert result == "some-model"

    def test_normalize_model_id_anthropic_openrouter_slash_format(self) -> None:
        """Cover openrouter with anthropic prefix - dot replacement path."""
        result = normalize_model_id("openrouter", "anthropic/claude-sonnet-4.6")
        assert result == "anthropic/claude-sonnet-4.6"

    def test_normalize_model_id_anthropic_vercel_gateway_no_match(self) -> None:
        """Cover vercel-ai-gateway with non-matching pattern."""
        result = normalize_model_id("vercel-ai-gateway", "claude-sonnet-4")
        assert result == "claude-sonnet-4"

    def test_list_aliases_empty_for_unknown_provider(self) -> None:
        """list_aliases with provider not in map returns empty."""
        result = list_aliases("no_such_provider")
        assert result == {"no_such_provider": {}}

    def test_register_alias_overwrites(self) -> None:
        """Cover overwriting existing alias."""
        register_alias("anthropic", "opus", "claude-opus-5")
        assert _PROVIDER_ALIASES["anthropic"]["opus"] == "claude-opus-5"

    def test_register_alias_lowercases_provider(self) -> None:
        """Cover provider normalization in register_alias."""
        register_alias("UPPERCASE_PROVIDER", "a", "b")
        assert "uppercase_provider" in _PROVIDER_ALIASES

    def test_normalize_empty_model_id(self) -> None:
        """Cover line 68: return model_id when empty."""
        result = normalize_model_id("gemini", "")
        assert result == ""

    def test_normalize_anthropic_dot_replacement(self) -> None:
        """Cover lines 90-95: anthropic dot-to-dash normalization."""
        result = normalize_model_id("anthropic", "claude-opus-4.8")
        assert result == "claude-opus-4-8"

    def test_normalize_anthropic_sonnet_dot(self) -> None:
        """Cover anthropic sonnet with dot."""
        result = normalize_model_id("anthropic", "sonnet-4.6")
        assert result == "claude-sonnet-4-6"

    def test_normalize_xai_dot_replacement(self) -> None:
        """Cover lines 99-104: xAI dot-to-dash normalization."""
        result = normalize_model_id("xai", "grok-2.17-reasoning")
        assert result == "grok-2-17-reasoning"

    def test_resolve_alias_exact_match(self) -> None:
        """Cover lines 116-117: resolve_alias with matching alias."""
        result = resolve_alias("anthropic", "opus")
        assert result == "claude-opus-4-8"

    def test_list_aliases_all(self) -> None:
        """Cover line 126: list_aliases without provider."""
        all_aliases = list_aliases()
        assert isinstance(all_aliases, dict)
        assert "anthropic" in all_aliases

    def test_gemini_no_regex_match(self) -> None:
        """Cover branch 80->87: gemini provider with non-matching model_id."""
        result = normalize_model_id("gemini", "some-other-model")
        assert result == "some-other-model"

    def test_xai_no_regex_match(self) -> None:
        """Cover branch 100->106: xAI provider with non-matching model_id."""
        result = normalize_model_id("xai", "some-other-model")
        assert result == "some-other-model"

    def test_resolve_alias_no_match(self) -> None:
        """Cover branch 116->118: provider exists but alias not found."""
        result = resolve_alias("anthropic", "nonexistent-alias")
        assert result == "nonexistent-alias"