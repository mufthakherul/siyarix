from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.workflow_generator import (
    BUILTIN_TEMPLATES,
    GeneratedWorkflow,
    TemplateCategory,
    WorkflowGenerator,
    WorkflowTemplate,
    WorkflowValidator,
)


# ── WorkflowTemplate Tests ──────────────────────────────────────────────


class TestWorkflowTemplate:
    def test_create_template(self) -> None:
        t = WorkflowTemplate(
            name="Test",
            category=TemplateCategory.CUSTOM,
            description="A test",
            steps=[{"id": "s1", "tool": "echo", "args": ["hello"]}],
            variables=["msg"],
            estimated_duration="1 min",
            risk_level="low",
        )
        assert t.name == "Test"
        assert t.category == TemplateCategory.CUSTOM
        assert t.estimated_duration == "1 min"

    def test_render_substitutes_variables(self) -> None:
        t = WorkflowTemplate(
            name="Render Test",
            category=TemplateCategory.SCAN,
            description="test",
            steps=[{"tool": "nmap", "args": ["${target}"]}],
            variables=["target"],
        )
        result = t.render(target="10.0.0.1")
        assert result["steps"][0]["args"] == ["10.0.0.1"]

    def test_render_substitutes_parentheses(self) -> None:
        t = WorkflowTemplate(
            name="Paren Test",
            category=TemplateCategory.SCAN,
            description="test",
            steps=[{"tool": "nmap", "args": ["$(target)"]}],
            variables=["target"],
        )
        result = t.render(target="example.com")
        assert result["steps"][0]["args"] == ["example.com"]

    def test_render_multiple_variables(self) -> None:
        t = WorkflowTemplate(
            name="Multi",
            category=TemplateCategory.CUSTOM,
            description="test",
            steps=[{"tool": "nmap", "args": ["${host}", "${port}"]}],
            variables=["host", "port"],
        )
        result = t.render(host="10.0.0.1", port="443")
        assert result["steps"][0]["args"] == ["10.0.0.1", "443"]

    def test_render_returns_category_value(self) -> None:
        t = WorkflowTemplate(
            name="CatTest",
            category=TemplateCategory.RECON,
            description="test",
            steps=[],
        )
        result = t.render()
        assert result["category"] == "recon"

    def test_render_returns_name(self) -> None:
        t = WorkflowTemplate(
            name="MyTemplate",
            category=TemplateCategory.CUSTOM,
            description="",
            steps=[],
        )
        result = t.render()
        assert result["name"] == "MyTemplate"

    def test_render_returns_variables(self) -> None:
        t = WorkflowTemplate(
            name="VarTest",
            category=TemplateCategory.CUSTOM,
            description="",
            steps=[],
            variables=["a", "b"],
        )
        result = t.render(a="1", b="2")
        assert result["variables"] == {"a": "1", "b": "2"}


# ── Built-in Templates Tests ────────────────────────────────────────────


class TestBuiltinTemplates:
    def test_all_templates_present(self) -> None:
        assert "full-recon" in BUILTIN_TEMPLATES
        assert "webapp-scan" in BUILTIN_TEMPLATES
        assert "network-sweep" in BUILTIN_TEMPLATES
        assert "quick-check" in BUILTIN_TEMPLATES

    def test_full_recon_structure(self) -> None:
        t = BUILTIN_TEMPLATES["full-recon"]
        assert len(t.steps) == 5
        assert t.variables == ["target"]
        assert t.category == TemplateCategory.RECON

    def test_webapp_scan_structure(self) -> None:
        t = BUILTIN_TEMPLATES["webapp-scan"]
        assert len(t.steps) == 5
        assert t.variables == ["target_url"]

    def test_network_sweep_structure(self) -> None:
        t = BUILTIN_TEMPLATES["network-sweep"]
        assert len(t.steps) == 4
        assert t.variables == ["network_range"]

    def test_quick_check_structure(self) -> None:
        t = BUILTIN_TEMPLATES["quick-check"]
        assert len(t.steps) == 3
        assert t.variables == ["target"]

    def test_risk_levels(self) -> None:
        assert BUILTIN_TEMPLATES["full-recon"].risk_level == "low"
        assert BUILTIN_TEMPLATES["webapp-scan"].risk_level == "medium"
        assert BUILTIN_TEMPLATES["quick-check"].risk_level == "low"


# ── GeneratedWorkflow Tests ─────────────────────────────────────────────


class TestGeneratedWorkflow:
    def test_to_yaml_dict_structure(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_001",
            name="Test WF",
            description="A test",
            steps=[{"id": "s1", "tool": "nmap"}],
            source="template",
            template_name="full-recon",
            estimated_duration="10m",
            risk_level="low",
        )
        d = wf.to_yaml_dict()
        assert "workflow" in d
        assert d["workflow"]["id"] == "wf_001"
        assert d["workflow"]["name"] == "Test WF"
        assert d["workflow"]["source"] == "template"
        assert d["workflow"]["estimated_duration"] == "10m"

    def test_to_yaml_dict_defaults(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_002",
            name="Default Test",
            description="",
            steps=[],
            source="custom",
        )
        d = wf.to_yaml_dict()
        assert d["workflow"]["risk_level"] == "low"
        assert d["workflow"]["estimated_duration"] == ""
        assert d["workflow"]["variables"] == {}

    def test_created_at_default(self) -> None:
        wf = GeneratedWorkflow(workflow_id="wf_003", name="N", description="D", steps=[], source="ai")
        assert wf.created_at is not None

    def test_save_yaml_json_fallback(self, tmp_path: Path) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_005",
            name="JSON Fallback",
            description="No pyyaml",
            steps=[{"id": "s1", "tool": "echo"}],
            source="custom",
        )
        path = tmp_path / "test.yaml"
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No yaml")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            wf.save_yaml(path)

        json_path = path.with_suffix(".json")
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert data["workflow"]["id"] == "wf_005"

    def test_save_yaml_creates_directory(self, tmp_path: Path) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_006",
            name="Dir Test",
            description="Create parent dirs",
            steps=[],
            source="custom",
        )
        path = tmp_path / "a" / "b" / "c" / "test.yaml"
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No yaml")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            wf.save_yaml(path)
        assert path.parent.exists()

    def test_save_yaml_uses_yaml_when_available(self, tmp_path: Path) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_004",
            name="YAML Test",
            description="Saving as YAML",
            steps=[{"id": "s1", "tool": "echo"}],
            source="template",
        )
        path = tmp_path / "test_output.yaml"

        try:
            import importlib.util
            has_yaml = importlib.util.find_spec("yaml") is not None
        except Exception:
            has_yaml = False

        if has_yaml:
            wf.save_yaml(path)
            assert path.exists()
            content = path.read_text()
            assert "wf_004" in content
        else:
            import builtins
            original_import = builtins.__import__

            def mock_import(name, *args, **kwargs):
                if name == "yaml":
                    raise ImportError("No yaml")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                wf.save_yaml(path)
            json_path = path.with_suffix(".json")
            assert json_path.exists()


# ── WorkflowValidator Tests ─────────────────────────────────────────────


class TestWorkflowValidator:
    def test_valid_workflow(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_v1",
            name="Valid",
            description="OK",
            steps=[
                {"id": "s1", "tool": "nmap", "args": ["-sV"]},
                {"id": "s2", "tool": "nuclei", "args": ["-u", "x"], "depends_on": ["s1"]},
            ],
            source="custom",
        )
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert errors == []

    def test_no_steps(self) -> None:
        wf = GeneratedWorkflow(workflow_id="wf_e1", name="E", description="", steps=[], source="custom")
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert "Workflow has no steps" in errors

    def test_step_no_id(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_e2",
            name="E",
            description="",
            steps=[{"tool": "nmap", "args": ["-sV"]}],
            source="custom",
        )
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert any("no 'id' field" in e for e in errors)

    def test_duplicate_step_id(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_e3",
            name="E",
            description="",
            steps=[
                {"id": "s1", "tool": "nmap"},
                {"id": "s1", "tool": "nuclei"},
            ],
            source="custom",
        )
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert any("Duplicate step id" in e for e in errors)

    def test_unknown_dependency(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_e4",
            name="E",
            description="",
            steps=[
                {"id": "s1", "tool": "nmap", "depends_on": ["nonexistent"]},
            ],
            source="custom",
        )
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert any("depends on unknown step" in e for e in errors)

    def test_no_tool_or_command(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_e5",
            name="E",
            description="",
            steps=[
                {"id": "s1"},
            ],
            source="custom",
        )
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert any("no 'tool' or 'command'" in e for e in errors)

    def test_report_step_no_tool_needed(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_e6",
            name="E",
            description="",
            steps=[
                {"id": "r1", "step_type": "report"},
            ],
            source="custom",
        )
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert errors == []

    def test_command_field_accepted(self) -> None:
        wf = GeneratedWorkflow(
            workflow_id="wf_e7",
            name="E",
            description="",
            steps=[
                {"id": "s1", "command": "custom script"},
            ],
            source="custom",
        )
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert errors == []

    def test_empty_workflow_id(self) -> None:
        wf = GeneratedWorkflow(workflow_id="", name="N", description="", steps=[{"id": "s1", "tool": "t"}], source="c")
        validator = WorkflowValidator()
        errors = validator.validate(wf)
        assert errors == []


# ── WorkflowGenerator Tests ─────────────────────────────────────────────


class TestWorkflowGenerator:
    def test_list_templates(self) -> None:
        gen = WorkflowGenerator()
        templates = gen.list_templates()
        assert len(templates) == 4
        for t in templates:
            assert "name" in t
            assert "key" in t
            assert "category" in t
            assert "step_count" in t

    def test_from_template_valid(self) -> None:
        gen = WorkflowGenerator()
        wf = gen.from_template("full-recon", target="example.com")
        assert wf.source == "template"
        assert wf.template_name == "full-recon"
        assert wf.variables == {"target": "example.com"}
        assert len(wf.steps) > 0

    def test_from_template_invalid(self) -> None:
        gen = WorkflowGenerator()
        with pytest.raises(ValueError, match="Unknown template"):
            gen.from_template("nonexistent-template")

    def test_from_template_with_validation_no_warning(self) -> None:
        gen = WorkflowGenerator()
        with patch("siyarix.workflow_generator.logger") as mock_log:
            gen.from_template("full-recon", target="example.com")
            mock_log.warning.assert_not_called()

    def test_from_template_quick_check(self) -> None:
        gen = WorkflowGenerator()
        wf = gen.from_template("quick-check", target="10.0.0.1")
        assert len(wf.steps) == 3
        assert wf.risk_level == "low"

    @pytest.mark.asyncio
    async def test_from_natural_language(self) -> None:
        gen = WorkflowGenerator()
        wf = await gen.from_natural_language("Scan target for vulnerabilities", target="10.0.0.1")
        assert wf.source == "ai"
        assert "Scan target for vulnerabilities" in wf.name
        assert len(wf.steps) > 0

    @pytest.mark.asyncio
    async def test_from_natural_language_no_target(self) -> None:
        gen = WorkflowGenerator()
        wf = await gen.from_natural_language("Scan for vulnerabilities")
        assert wf.variables == {}

    @pytest.mark.asyncio
    async def test_from_natural_language_empty_context(self) -> None:
        gen = WorkflowGenerator()
        wf = await gen.from_natural_language("Check host", context={})
        assert wf.source == "ai"

    def test_decompose_goal_recon(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("reconnaissance and discover", "example.com")
        assert any("nmap" in str(s) for s in steps)
        assert any("report" in str(s) for s in steps)

    def test_decompose_goal_scan(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("vulnerability scan", "10.0.0.1")
        assert any("nuclei" in str(s) for s in steps)
        assert any("report" in str(s) for s in steps)

    def test_decompose_goal_webapp(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("web application sql injection", "example.com")
        assert any("nikto" in str(s) for s in steps)
        assert any("report" in str(s) for s in steps)

    def test_decompose_goal_subdomain(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("enumerate subdomains for example.com", "")
        assert any("subfinder" in str(s) for s in steps)
        assert any("report" in str(s) for s in steps)

    def test_decompose_goal_directory(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("brute force directories", "example.com")
        assert any("gobuster" in str(s) for s in steps)
        assert any("report" in str(s) for s in steps)

    def test_decompose_goal_fallback(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("just a random query", "")
        assert len(steps) == 2
        assert steps[0]["tool"] == "nmap"
        assert steps[-1]["step_type"] == "report"

    def test_decompose_goal_multiple_keywords(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("recon and scan and web vulnerabilities", "target")
        step_ids = {s["id"] for s in steps if "step_type" not in s}
        assert len(step_ids) >= 3

    def test_estimate_risk_high(self) -> None:
        gen = WorkflowGenerator()
        assert gen._estimate_risk("exploit the target") == "high"
        assert gen._estimate_risk("send payload to reverse shell") == "high"
        assert gen._estimate_risk("brute force attack") == "high"

    def test_estimate_risk_medium(self) -> None:
        gen = WorkflowGenerator()
        assert gen._estimate_risk("run vulnerability scan") == "medium"
        assert gen._estimate_risk("pentest the webapp") == "medium"
        assert gen._estimate_risk("sql injection test") == "medium"

    def test_estimate_risk_low(self) -> None:
        gen = WorkflowGenerator()
        assert gen._estimate_risk("list all dns records") == "low"
        assert gen._estimate_risk("normal operation") == "low"

    def test_from_natural_language_adds_report_step(self) -> None:
        gen = WorkflowGenerator()
        steps = gen._decompose_goal("scan stuff", "target")
        assert steps[-1]["step_type"] == "report"

    def test_generator_uses_validator(self) -> None:
        gen = WorkflowGenerator()
        assert gen._validator is not None
        assert isinstance(gen._validator, WorkflowValidator)

    def test_template_category_values(self) -> None:
        assert TemplateCategory.RECON.value == "recon"
        assert TemplateCategory.SCAN.value == "scan"
        assert TemplateCategory.WEBAPP.value == "webapp"
        assert TemplateCategory.NETWORK.value == "network"
        assert TemplateCategory.PENTEST.value == "pentest"
        assert TemplateCategory.COMPLIANCE.value == "compliance"
        assert TemplateCategory.CUSTOM.value == "custom"

    @pytest.mark.asyncio
    async def test_from_natural_language_validation_logs_warning(self) -> None:
        gen = WorkflowGenerator()
        with patch("siyarix.workflow_generator.logger") as mock_log:
            with patch.object(gen._validator, "validate", return_value=["Test error"]):
                await gen.from_natural_language("test goal")
                mock_log.warning.assert_called_once()
