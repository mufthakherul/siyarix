# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for persona_engine.py — PersonaEngine (172 stmts, ~44% covered)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from siyarix.persona_engine import (
    BUILTIN_PERSONAS,
    LearningBias,
    Persona,
    PersonaEngine,
    PersonaName,
    ToolACL,
    WorkflowTemplate,
)


# ---------------------------------------------------------------------------
# ToolACL
# ---------------------------------------------------------------------------

class TestToolACL:
    def test_is_allowed_wildcard(self):
        acl = ToolACL()
        assert acl.is_allowed("any_tool") is True

    def test_is_allowed_forbidden(self):
        acl = ToolACL(forbidden=["danger"])
        assert acl.is_allowed("danger") is False

    def test_is_allowed_explicit(self):
        acl = ToolACL(allowed=["nmap", "nuclei"], forbidden=[], auto_approve_seconds=5)
        assert acl.is_allowed("nmap") is True
        assert acl.is_allowed("unknown") is False

    def test_requires_permission(self):
        acl = ToolACL(permission_required=["msfconsole"])
        assert acl.requires_permission("msfconsole") is True
        assert acl.requires_permission("nmap") is False

    def test_requires_review(self):
        acl = ToolACL(review_required=["msfconsole"])
        assert acl.requires_review("msfconsole") is True
        assert acl.requires_review("nmap") is False


# ---------------------------------------------------------------------------
# WorkflowTemplate
# ---------------------------------------------------------------------------

class TestWorkflowTemplate:
    def test_to_list(self):
        wf = WorkflowTemplate(steps=["Recon", "Scan", "Report"])
        assert wf.to_list() == ["Recon", "Scan", "Report"]

    def test_empty(self):
        wf = WorkflowTemplate()
        assert wf.to_list() == []


# ---------------------------------------------------------------------------
# Persona
# ---------------------------------------------------------------------------

class TestPersona:
    def test_to_dict(self):
        p = Persona(
            name="test_persona",
            description="test desc",
            system_prompt="prompt",
            tool_acl=ToolACL(allowed=["*"], forbidden=["sqlmap"]),
            workflow_template=WorkflowTemplate(steps=["A", "B"]),
            learning_bias=LearningBias.CAUTIOUS,
            tool_filter_category=["web"],
            is_custom=True,
            metadata={"version": 1},
        )
        d = p.to_dict()
        assert d["name"] == "test_persona"
        assert d["tool_acl"]["forbidden"] == ["sqlmap"]
        assert d["learning_bias"] == "cautious"
        assert d["is_custom"] is True

    def test_from_dict(self):
        data = {
            "name": "restored",
            "description": "restored desc",
            "system_prompt": "be safe",
            "tool_acl": {"allowed": ["*"], "forbidden": [], "permission_required": [],
                         "review_required": [], "auto_approve_seconds": 10},
            "workflow_template": ["Step1"],
            "learning_bias": "aggressive",
            "tool_filter_category": ["recon"],
            "is_custom": True,
            "metadata": {"k": "v"},
        }
        p = Persona.from_dict(data)
        assert p.name == "restored"
        assert p.learning_bias == LearningBias.AGGRESSIVE
        assert p.is_custom is True

    def test_from_dict_bad_learning_bias(self):
        data = {
            "name": "test",
            "system_prompt": "prompt",
            "learning_bias": "nonexistent",
            "tool_acl": {},
            "workflow_template": [],
        }
        p = Persona.from_dict(data)
        assert p.learning_bias == LearningBias.BALANCED

    def test_from_dict_wf_string(self):
        data = {
            "name": "test", "system_prompt": "p",
            "workflow_template": "just a string",
            "tool_acl": {},
        }
        p = Persona.from_dict(data)
        assert p.workflow_template.steps == []


# ---------------------------------------------------------------------------
# BUILTIN_PERSONAS
# ---------------------------------------------------------------------------

class TestBuiltinPersonas:
    def test_all_personas_present(self):
        assert PersonaName.OFFENSIVE in BUILTIN_PERSONAS
        assert PersonaName.DEFENSIVE in BUILTIN_PERSONAS
        assert PersonaName.BUG_HUNTER in BUILTIN_PERSONAS
        assert PersonaName.PENTESTER in BUILTIN_PERSONAS
        assert PersonaName.SOC_ANALYST in BUILTIN_PERSONAS
        assert PersonaName.NONE in BUILTIN_PERSONAS
        assert PersonaName.AUTO in BUILTIN_PERSONAS

    def test_offensive_persona(self):
        p = BUILTIN_PERSONAS[PersonaName.OFFENSIVE]
        assert p.learning_bias == LearningBias.AGGRESSIVE
        assert len(p.tool_acl.permission_required) > 0
        assert "msfconsole" in p.tool_acl.permission_required

    def test_defensive_persona(self):
        p = BUILTIN_PERSONAS[PersonaName.DEFENSIVE]
        assert "msfconsole" in p.tool_acl.forbidden


# ---------------------------------------------------------------------------
# PersonaEngine
# ---------------------------------------------------------------------------

class TestPersonaEngine:
    @pytest.fixture
    def engine(self, tmp_path):
        return PersonaEngine(personas_dir=tmp_path / "personas")

    def test_init_loads_builtins(self, engine):
        assert len(engine._personas) >= 6
        assert PersonaName.NONE in engine._personas

    def test_active_persona_none_at_start(self, engine):
        assert engine.active_persona is None

    def test_persona_list(self, engine):
        lst = engine.persona_list
        assert len(lst) >= 6

    def test_persona_names(self, engine):
        names = engine.persona_names
        assert "none" in names

    def test_get_persona(self, engine):
        p = engine.get_persona("offensive")
        assert p is not None
        assert p.name == "offensive"

    def test_get_persona_nonexistent(self, engine):
        assert engine.get_persona("nonexistent") is None

    def test_get_system_prompt_named(self, engine):
        prompt = engine.get_system_prompt("offensive")
        assert "offensive" in prompt.lower()

    def test_get_system_prompt_nonexistent_fallsback(self, engine):
        prompt = engine.get_system_prompt("nonexistent")
        assert prompt is not None

    def test_get_system_prompt_active(self, engine):
        engine.switch_to("bug_hunter")
        prompt = engine.get_system_prompt()
        assert "bug bounty" in prompt.lower()

    def test_get_system_prompt_auto(self, engine):
        prompt = engine.get_system_prompt("auto")
        assert prompt is not None

    def test_switch_to(self, engine):
        p = engine.switch_to("pentester")
        assert p.name == "pentester"
        assert engine.active_persona == p

    def test_switch_to_unknown(self, engine):
        with pytest.raises(ValueError, match="Unknown persona"):
            engine.switch_to("unknown")

    def test_classify_intent_vulnerability(self, engine):
        name, conf = engine.classify_intent("find vulnerabilities in webapp")
        assert name == PersonaName.BUG_HUNTER
        assert conf >= 0.87

    def test_classify_intent_exploit(self, engine):
        name, conf = engine.classify_intent("exploit the target")
        assert name == PersonaName.OFFENSIVE

    def test_classify_intent_incident(self, engine):
        name, conf = engine.classify_intent("respond to security incident")
        assert name == PersonaName.SOC_ANALYST

    def test_classify_intent_unknown(self, engine):
        name, conf = engine.classify_intent("hello world")
        assert name == PersonaName.NONE
        assert conf == 0.0

    def test_detect_and_switch_auto(self, engine):
        engine.switch_to("auto")
        p = engine.detect_and_switch("exploit the target")
        assert p.name == PersonaName.OFFENSIVE

    def test_detect_and_switch_not_auto(self, engine):
        engine.switch_to("none")
        p = engine.detect_and_switch("exploit the target")
        # Stays on "none" since active persona is not auto
        assert p.name == PersonaName.NONE

    def test_detect_and_switch_low_confidence(self, engine):
        engine.switch_to("auto")
        p = engine.detect_and_switch("random stuff")
        assert p is not None

    def test_get_filtered_tools(self, engine):
        engine.switch_to("bug_hunter")
        all_tools = ["nmap", "nuclei", "sqlmap", "metasploit"]
        filtered = engine.get_filtered_tools(all_tools)
        assert "nmap" in filtered
        assert "sqlmap" not in filtered

    def test_get_filtered_tools_no_active(self, engine):
        all_tools = ["nmap", "nuclei"]
        filtered = engine.get_filtered_tools(all_tools)
        assert filtered == all_tools

    def test_get_workflow_template(self, engine):
        steps = engine.get_workflow_template("offensive")
        assert "Reconnaissance" in steps

    def test_get_workflow_template_nonexistent(self, engine):
        steps = engine.get_workflow_template("nonexistent")
        assert steps == []

    def test_get_workflow_template_active(self, engine):
        engine.switch_to("soc_analyst")
        steps = engine.get_workflow_template()
        assert "Alert" in steps

    def test_save_custom_persona(self, engine, tmp_path):
        p = Persona(name="custom_1", system_prompt="custom prompt",
                     description="my custom persona")
        path = engine.save_custom_persona(p)
        assert path.exists()
        assert "custom_1" in engine._personas
        assert engine._personas["custom_1"].is_custom is True

    def test_save_custom_persona_yaml_fallback(self, engine, tmp_path):
        import builtins
        real_import = builtins.__import__
        def fake_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no yaml")
            return real_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=fake_import):
            p = Persona(name="custom_2", system_prompt="fallback prompt")
            path = engine.save_custom_persona(p)
            assert path.exists()
            content = path.read_text()
            assert "custom_2" in content

    def test_load_custom_personas(self, engine, tmp_path):
        custom_dir = tmp_path / "personas" / "custom"
        custom_dir.mkdir(parents=True, exist_ok=True)
        yaml_file = custom_dir / "my_persona.yaml"
        yaml_file.write_text(json.dumps({
            "name": "my_persona",
            "system_prompt": "my prompt",
            "description": "my custom",
            "tool_acl": {"allowed": ["*"], "forbidden": []},
            "workflow_template": [],
            "learning_bias": "balanced",
        }))
        engine._load_all()
        assert "my_persona" in engine._personas

    def test_load_custom_personas_no_dir(self, engine, tmp_path):
        # custom dir does not exist
        engine._custom_dir = tmp_path / "nonexistent"
        result = engine._load_custom_personas()
        assert result == {}
