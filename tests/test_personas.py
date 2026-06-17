# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exhaustive tests for personas.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from siyarix.chat.prompts import _platform_context
from siyarix.personas import (
    PERSONAS,
    build_persona_prompt,
    get_persona,
    list_personas,
)


class TestPersonasConstants:
    def test_all_personas_defined(self):
        expected_keys = {
            "universal", "auto", "none", "red team", "blue team",
            "purple team", "dfir", "threat intelligence", "cloud security",
            "appsec", "network security", "governance", "security explorer",
        }
        assert set(PERSONAS.keys()) == expected_keys

    def test_each_persona_has_required_keys(self):
        for name, p in PERSONAS.items():
            assert "name" in p
            assert "label" in p
            assert "description" in p
            assert "prompt" in p
            assert p["name"] == name

    def test_auto_and_none_have_empty_prompt(self):
        assert PERSONAS["auto"]["prompt"] == ""
        assert PERSONAS["none"]["prompt"] == ""

    def test_universal_has_prompt(self):
        assert len(PERSONAS["universal"]["prompt"]) > 0


# ── get_persona ──────────────────────────────────────────────────────────

class TestGetPersona:
    def test_exact_match(self):
        p = get_persona("red team")
        assert p is not None
        assert p["name"] == "red team"

    def test_case_insensitive_fallback(self):
        p = get_persona("Red Team")
        assert p is not None
        assert p["name"] == "red team"

    def test_case_insensitive_mixed(self):
        p = get_persona("BLUE TEAM")
        assert p is not None
        assert p["name"] == "blue team"

    def test_not_found_returns_none(self):
        p = get_persona("nonexistent_persona")
        assert p is None

    def test_empty_string_returns_none(self):
        p = get_persona("")
        assert p is None

    def test_all_personas_retrievable(self):
        for name in PERSONAS:
            p = get_persona(name)
            assert p is not None
            assert p["name"] == name

    def test_partial_match_does_not_fallback(self):
        p = get_persona("team")
        assert p is None


# ── list_personas ────────────────────────────────────────────────────────

class TestListPersonas:
    def test_excludes_auto_none_and_universal(self):
        personas = list_personas()
        names = [p["name"] for p in personas]
        assert "auto" not in names
        assert "none" not in names
        assert "universal" not in names

    def test_returns_all_other_personas(self):
        personas = list_personas()
        expected = [
            "red team", "blue team", "purple team", "dfir",
            "threat intelligence", "cloud security", "appsec",
            "network security", "governance", "security explorer",
        ]
        names = [p["name"] for p in personas]
        for name in expected:
            assert name in names
        assert len(personas) == len(expected)

    def test_each_returned_persona_is_dict(self):
        personas = list_personas()
        for p in personas:
            assert isinstance(p, dict)
            assert "name" in p
            assert "label" in p
            assert "description" in p

    def test_list_is_deterministic_order(self):
        p1 = list_personas()
        p2 = list_personas()
        assert [p["name"] for p in p1] == [p["name"] for p in p2]


# ── build_persona_prompt ─────────────────────────────────────────────────

class TestBuildPersonaPrompt:
    def test_none_returns_empty_string(self):
        prompt = build_persona_prompt("none")
        assert prompt == ""

    def test_unknown_returns_empty_string(self):
        prompt = build_persona_prompt("unknown_persona")
        assert prompt == ""

    def test_auto_returns_all_persona_descriptions(self):
        prompt = build_persona_prompt("auto")
        assert "## Active Persona: Auto (Smart Select)" in prompt
        assert "Available personas:" in prompt
        # Should include descriptions of all non-auto, non-none personas
        for name, pp in PERSONAS.items():
            if name not in ("auto", "none"):
                assert pp["label"] in prompt
                assert pp["description"] in prompt
        assert "After selecting the persona" in prompt

    def test_universal_returns_prompt(self):
        prompt = build_persona_prompt("universal")
        assert "## Active Persona: Universal / All-in-One" in prompt
        assert "elite cybersecurity generalist" in prompt

    def test_named_persona_returns_prompt(self):
        prompt = build_persona_prompt("red team")
        assert "## Active Persona: Red Team / Offensive Security" in prompt
        assert "adversary emulation" in prompt

    def test_blue_team_prompt_returned(self):
        prompt = build_persona_prompt("blue team")
        assert "## Active Persona: Blue Team / Defensive Security" in prompt
        assert "detection logic" in prompt

    def test_purple_team_prompt_returned(self):
        prompt = build_persona_prompt("purple team")
        assert "## Active Persona: Purple Team / Collaborative Security" in prompt
        assert "adversary emulation exercises" in prompt

    def test_dfir_prompt_returned(self):
        prompt = build_persona_prompt("dfir")
        assert "## Active Persona: DFIR / Digital Forensics & Incident Response" in prompt
        assert "master DFIR investigator" in prompt

    def test_threat_intelligence_prompt_returned(self):
        prompt = build_persona_prompt("threat intelligence")
        assert "## Active Persona: Threat Intelligence / CTI" in prompt
        assert "senior CTI analyst" in prompt

    def test_cloud_security_prompt_returned(self):
        prompt = build_persona_prompt("cloud security")
        assert "## Active Persona: Cloud Security / CloudSec" in prompt
        assert "cloud security authority" in prompt

    def test_appsec_prompt_returned(self):
        prompt = build_persona_prompt("appsec")
        assert "## Active Persona: Application Security / AppSec" in prompt
        assert "elite application security engineer" in prompt

    def test_network_security_prompt_returned(self):
        prompt = build_persona_prompt("network security")
        assert "## Active Persona: Network Security / NetSec" in prompt
        assert "network security expert" in prompt

    def test_governance_prompt_returned(self):
        prompt = build_persona_prompt("governance")
        assert "## Active Persona: Governance / GRC" in prompt
        assert "senior GRC professional" in prompt

    def test_security_explorer_prompt_returned(self):
        prompt = build_persona_prompt("security explorer")
        assert "## Active Persona: Security Explorer / Research" in prompt
        assert "security researcher driven" in prompt

    def test_prompt_starts_with_persona_header(self):
        for name in PERSONAS:
            if name in ("auto", "none"):
                continue
            prompt = build_persona_prompt(name)
            assert prompt.startswith("## Active Persona:")


# ── Edge cases ──────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_build_prompt_with_case_insensitive_name(self):
        prompt = build_persona_prompt("Red Team")
        assert "Red Team / Offensive Security" in prompt

    def test_get_persona_matches_case_insensitively(self):
        p = get_persona("CLOUD SECURITY")
        assert p is not None
        assert p["name"] == "cloud security"

class TestPromptsPlatformContext:
    """Cover prompts.py line 34 (non-Windows path in _platform_context)."""

    def test_platform_context_non_windows(self):
        with patch("sys.platform", "linux"):
            from siyarix.chat.prompts import _platform_context
            ctx = _platform_context()
            assert "Unix-like system" in ctx


# ═══════════════════════════════════════════════════════════════════
# chat/session.py (65% - missing 48-52, 56, 61, 63, 79-93, 108-111)
# ═══════════════════════════════════════════════════════════════════
class TestPromptsWindows:
    """Cover prompts.py line 24 (Windows path in _platform_context)."""

    def test_platform_context_windows(self):
        with patch("sys.platform", "win32"):
            ctx = _platform_context()
            assert "WARNING: Windows system detected" in ctx

    def test_platform_context_non_windows_already_covered(self):
        with patch("sys.platform", "linux"):
            ctx = _platform_context()
            assert "Unix-like system" in ctx


# ═══════════════════════════════════════════════════════════════════
# 4. chat/openai_compat.py (87% - many uncovered lines)
# ═══════════════════════════════════════════════════════════════════
class TestPromptsOpenAICompat:
    """Cover prompts.py line 24 (Windows path in _platform_context)."""

    def test_platform_context_windows(self):
        with patch("sys.platform", "win32"):
            ctx = _platform_context()
            assert "WARNING: Windows system detected" in ctx

    def test_platform_context_non_windows_already_covered(self):
        with patch("sys.platform", "linux"):
            ctx = _platform_context()
            assert "Unix-like system" in ctx


# ═══════════════════════════════════════════════════════════════════
# 4. chat/openai_compat.py (87% - many uncovered lines)
# ═══════════════════════════════════════════════════════════════════
class TestPromptsWindowsPath:
    """Line 24: lines.extend() inside if is_win."""

    def test_platform_context_windows(self):
        with patch("sys.platform", "win32"):
            ctx = _platform_context()
            assert "WARNING: Windows system detected" in ctx
            assert "nmap: use -sT" in ctx
            assert "nslookup" in ctx
            assert "where" in ctx


# ═══════════════════════════════════════════════════════════════════
# 3. chat/session.py (99% - missing 82->84) — branch() condition
# ═══════════════════════════════════════════════════════════════════
