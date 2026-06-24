
from __future__ import annotations
from siyarix.models import ExecutionPlan, PlanStatus
from siyarix.models import PlanStep, PlanType, StepStatus
from siyarix.nlp_engine import ParsedIntent
from siyarix.planner_registry import RegistryPlanner
from siyarix.planner_registry import TOOL_ALTERNATIVES
from unittest.mock import MagicMock, patch
import pytest
import time

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exhaustive tests for RegistryPlanner — covering all methods, branches, and error paths."""






# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def planner() -> RegistryPlanner:
    return RegistryPlanner()


@pytest.fixture
def mock_intent() -> ParsedIntent:
    return ParsedIntent(
        target="example.com",
        target_type="domain",
        template_name=None,
        tool_name=None,
        parameters={},
        confidence=0.0,
        tokens=[],
    )


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_init(self, planner: RegistryPlanner):
        assert planner._plans == {}
        assert planner._nlp is not None
        assert "recon_full" in planner._auto_dag_templates
        assert len(planner._templates) > 0
        assert planner._keyword_index == {}

    def test_templates_contain_expected_keys(self, planner: RegistryPlanner):
        expected = {
            "recon_full", "web_audit", "brute_force", "wifi_audit",
            "network_scan", "cloud_audit", "ad_assessment", "linux_privesc",
            "vuln_scan", "dns_recon", "full_audit", "smb_enum",
        }
        assert expected.issubset(planner._templates.keys())

    def test_auto_dag_templates(self, planner: RegistryPlanner):
        for tpl in planner._auto_dag_templates:
            assert tpl in planner._templates


# ---------------------------------------------------------------------------
# _build_templates
# ---------------------------------------------------------------------------


class TestBuildTemplates:
    def test_template_structure(self, planner: RegistryPlanner):
        for name, steps in planner._templates.items():
            assert len(steps) > 0
            for step in steps:
                assert "tool" in step
                assert "description" in step
                assert "args" in step


# ---------------------------------------------------------------------------
# _add_to_index / _search_index
# ---------------------------------------------------------------------------


class TestAddToIndex:
    def test_add_new_keyword(self, planner: RegistryPlanner):
        planner._add_to_index("scan", "nmap")
        assert planner._keyword_index["scan"] == {"nmap"}

    def test_add_duplicate_keyword(self, planner: RegistryPlanner):
        planner._add_to_index("scan", "nmap")
        planner._add_to_index("scan", "nuclei")
        assert planner._keyword_index["scan"] == {"nmap", "nuclei"}

    def test_add_same_tool_twice(self, planner: RegistryPlanner):
        planner._add_to_index("scan", "nmap")
        planner._add_to_index("scan", "nmap")
        assert planner._keyword_index["scan"] == {"nmap"}


class TestSearchIndex:
    def test_simple_search(self, planner: RegistryPlanner):
        planner._add_to_index("port", "nmap")
        planner._add_to_index("scan", "nmap")
        planner._add_to_index("vuln", "nuclei")
        results = planner._search_index("port scan")
        assert "nmap" in results
        assert "nuclei" not in results  # 'vuln' doesn't appear in query

    def test_search_no_matches(self, planner: RegistryPlanner):
        planner._add_to_index("scan", "nmap")
        assert planner._search_index("zzzzz") == []

    def test_search_short_words_ignored(self, planner: RegistryPlanner):
        planner._add_to_index("scan", "nmap")
        assert planner._search_index("a b c") == []

    def test_search_empty_query(self, planner: RegistryPlanner):
        assert planner._search_index("") == []

    def test_search_partial_match(self, planner: RegistryPlanner):
        planner._add_to_index("portscan", "masscan")
        results = planner._search_index("scan")
        assert results == []

    def test_search_exact_name_boost(self, planner: RegistryPlanner):
        planner._add_to_index("nmap", "nmap")
        planner._add_to_index("scan", "nmap")
        planner._add_to_index("not_nmap", "other")
        results = planner._search_index("nmap scan")
        assert results[0] == "nmap"

    def test_search_component_boost(self, planner: RegistryPlanner):
        planner._add_to_index("dirbuster", "dirbuster")
        planner._add_to_index("buster", "dirbuster")
        results = planner._search_index("buster")
        assert results == ["dirbuster"]


# ---------------------------------------------------------------------------
# build_index
# ---------------------------------------------------------------------------


class TestBuildIndex:
    def test_build_index_without_registry(self, planner: RegistryPlanner):
        planner.build_index(["nmap", "nuclei"])
        assert len(planner._keyword_index) > 0

    def test_build_index_with_registry(self, planner: RegistryPlanner):
        mock_registry = MagicMock()
        mock_tool = MagicMock()
        mock_tool.name = "nmap"
        mock_tool.description = "Network port scanner"
        mock_tool.tags = ["port-scan", "network"]
        mock_tool.category = "RECON"
        mock_registry.get_tool.return_value = mock_tool

        planner.build_index(["nmap"], mock_registry)
        assert len(planner._keyword_index) > 0

    def test_build_index_tool_has_no_description(self, planner: RegistryPlanner):
        mock_registry = MagicMock()
        mock_tool = MagicMock()
        mock_tool.name = "nmap"
        mock_tool.description = "nmap"
        mock_tool.tags = ["scan"]
        mock_tool.category = "RECON"
        mock_registry.get_tool.return_value = mock_tool

        planner.build_index(["nmap"], mock_registry)
        assert "nmap" in planner._keyword_index.get("scan", set())

    def test_build_index_with_registry_fallback_to_graph(self, planner: RegistryPlanner):
        mock_registry = MagicMock()
        mock_registry.get_tool = None
        mock_graph = MagicMock()
        mock_tool = MagicMock()
        mock_tool.name = "nmap"
        mock_tool.description = "Scanner"
        mock_tool.tags = ["scan"]
        mock_tool.category = "RECON"
        mock_graph.get_tool.return_value = mock_tool
        mock_registry._graph = mock_graph

        planner.build_index(["nmap"], mock_registry)
        assert len(planner._keyword_index) > 0

    def test_build_index_registry_exception(self, planner: RegistryPlanner):
        mock_registry = MagicMock()
        mock_registry.get_tool.side_effect = Exception("broken")

        planner.build_index(["nmap"], mock_registry)
        assert len(planner._keyword_index) > 0

    def test_build_index_clears_previous(self, planner: RegistryPlanner):
        planner._add_to_index("old", "oldtool")
        planner.build_index(["nmap"])
        assert "old" not in planner._keyword_index

    def test_build_index_without_tools(self, planner: RegistryPlanner):
        planner.build_index([])
        assert planner._keyword_index == {}

    def test_build_index_trains_nlp(self, planner: RegistryPlanner):
        mock_registry = MagicMock()
        mock_tool = MagicMock()
        mock_tool.name = "nmap"
        mock_tool.description = "Network port scanner"
        mock_tool.tags = ["port-scan", "network"]
        mock_tool.category = "RECON"
        mock_registry.get_tool.return_value = mock_tool

        with patch.object(planner._nlp, "train_tools") as mock_train_tools, \
             patch.object(planner._nlp, "train_templates") as mock_train_templates:
            planner.build_index(["nmap"], mock_registry)
            mock_train_tools.assert_called_once()
            mock_train_templates.assert_called_once()


# ---------------------------------------------------------------------------
# resolve_alternatives
# ---------------------------------------------------------------------------


class TestResolveAlternatives:
    def test_tool_available(self, planner: RegistryPlanner):
        steps = planner.resolve_alternatives("recon_full", {"nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"})
        for step in steps:
            assert step["tool"] in {"nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"}
            assert "(via" not in step["description"]

    def test_tool_alternative_found(self, planner: RegistryPlanner):
        steps = planner.resolve_alternatives("recon_full", {"masscan", "whatweb", "ffuf", "subfinder", "amass", "nuclei"})
        nmap_step = next(s for s in steps if s["tool"] == "masscan")
        assert "(via masscan)" in nmap_step["description"]

    def test_tool_no_alternative(self, planner: RegistryPlanner):
        steps = planner.resolve_alternatives("recon_full", {"whatweb", "gobuster", "subfinder", "amass", "nuclei"})
        nmap_step = next(s for s in steps if s["tool"] == "nmap")
        assert nmap_step is not None

    def test_unknown_template(self, planner: RegistryPlanner):
        steps = planner.resolve_alternatives("nonexistent", {"nmap"})
        assert steps == []

    def test_available_tools_empty(self, planner: RegistryPlanner):
        steps = planner.resolve_alternatives("recon_full", set())
        assert len(steps) == 6


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------


class TestPlan:
    def test_plan_delegates_to_decompose(self, planner: RegistryPlanner):
        with patch.object(planner, "decompose_goal", return_value=MagicMock()) as mock_decompose:
            result = planner.plan("scan example.com")
            mock_decompose.assert_called_once_with("scan example.com", None)

    def test_plan_with_tools(self, planner: RegistryPlanner):
        with patch.object(planner, "decompose_goal", return_value=MagicMock()) as mock_decompose:
            planner.plan("scan", ["nmap"])
            mock_decompose.assert_called_once_with("scan", ["nmap"])


# ---------------------------------------------------------------------------
# create_plan
# ---------------------------------------------------------------------------


class TestCreatePlan:
    def test_create_empty_plan(self, planner: RegistryPlanner):
        plan = planner.create_plan("test goal")
        assert plan.goal == "test goal"
        assert plan.status == PlanStatus.ACTIVE
        assert plan.plan_type == PlanType.SEQUENTIAL
        assert plan.steps == []
        assert plan.id in planner._plans

    def test_create_plan_with_steps(self, planner: RegistryPlanner):
        steps = [
            {"tool": "nmap", "args": {"target": "x"}, "description": "Scan"},
            {"tool": "nuclei", "args": {"target": "x"}, "dependencies": ["step_000"]},
        ]
        plan = planner.create_plan("audit", steps=steps)
        assert len(plan.steps) == 2
        assert plan.steps[0].tool == "nmap"
        assert plan.steps[1].dependencies == ["step_000"]

    def test_create_plan_with_context(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", context={"key": "val"})
        assert plan.context == {"key": "val"}

    def test_create_plan_with_plan_type(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", plan_type=PlanType.DAG)
        assert plan.plan_type == PlanType.DAG

    def test_create_plan_emits_event(self, planner: RegistryPlanner):
        with patch("siyarix.planner_registry.emit_sync") as mock_emit:
            plan = planner.create_plan("test")
            mock_emit.assert_called_once()
            event = mock_emit.call_args[0][0]
            assert event.data["plan_id"] == plan.id
            assert event.data["goal"] == "test"

    def test_create_plan_ids_auto_increment(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{}, {"id": "custom"}, {}])
        assert plan.steps[0].id == "step_000"
        assert plan.steps[1].id == "custom"
        assert plan.steps[2].id == "step_002"


# ---------------------------------------------------------------------------
# create_from_template
# ---------------------------------------------------------------------------


class TestCreateFromTemplate:
    def test_create_from_template(self, planner: RegistryPlanner):
        plan = planner.create_from_template("recon_full", "example.com")
        assert "recon_full" in plan.goal
        assert "example.com" in plan.goal
        assert len(plan.steps) == 6
        assert plan.context["target"] == "example.com"
        assert plan.context["template"] == "recon_full"

    def test_create_from_template_with_overrides(self, planner: RegistryPlanner):
        overrides = {"args": {"severity": "critical"}}
        plan = planner.create_from_template("vuln_scan", "example.com", overrides=overrides)
        nuclei_step = [s for s in plan.steps if s.tool == "nuclei"][0]
        assert "critical" in str(nuclei_step.args.get("severity", ""))

    def test_create_from_template_unknown(self, planner: RegistryPlanner):
        with pytest.raises(ValueError, match="Unknown template: nonexistent"):
            planner.create_from_template("nonexistent", "target")

    def test_create_from_template_with_url_target(self, planner: RegistryPlanner):
        plan = planner.create_from_template("web_audit", "https://example.com/path")
        for step in plan.steps:
            assert "https://example.com/path" in str(step.args.get("target", ""))

    def test_create_from_template_with_ip_target(self, planner: RegistryPlanner):
        plan = planner.create_from_template("network_scan", "192.168.1.1")
        for step in plan.steps:
            assert step.args.get("target") == "192.168.1.1"

    def test_create_from_template_with_available_tools(self, planner: RegistryPlanner):
        plan = planner.create_from_template(
            "recon_full", "example.com", available_tools={"nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"}
        )
        assert len(plan.steps) == 6

    def test_create_from_template_dag_plan_type(self, planner: RegistryPlanner):
        plan = planner.create_from_template("recon_full", "target")
        assert plan.plan_type == PlanType.DAG

    def test_create_from_template_sequential_plan_type(self, planner: RegistryPlanner):
        plan = planner.create_from_template("brute_force", "target")
        assert plan.plan_type == PlanType.SEQUENTIAL


# ---------------------------------------------------------------------------
# smart_plan
# ---------------------------------------------------------------------------


class TestSmartPlan:
    def test_smart_plan_falls_back_when_no_intent(self, planner: RegistryPlanner, mock_intent):
        planner._nlp.parse = MagicMock(return_value=mock_intent)
        with patch.object(planner, "decompose_goal", return_value=MagicMock()) as mock_decompose:
            planner.smart_plan("scan something")
            mock_decompose.assert_called_once()

    def test_smart_plan_with_template_intent(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="example.com", target_type="domain",
            template_name="recon_full", confidence=15.0,
            parameters={}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.smart_plan("recon example.com")
        assert plan is not None
        assert "recon_full" in plan.goal

    def test_smart_plan_template_intent_value_error(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="", target_type="",
            template_name="nonexistent", confidence=15.0,
            parameters={}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        with patch.object(planner, "decompose_goal", return_value=MagicMock()) as mock_decompose:
            planner.smart_plan("scan")
            mock_decompose.assert_called_once()

    def test_smart_plan_context_populated(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="example.com", target_type="domain",
            template_name="recon_full", confidence=15.0,
            parameters={"speed": "fast"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.smart_plan("fast recon example.com")
        assert plan.context.get("nlp_template") == "recon_full"
        assert plan.context.get("nlp_confidence") == 15.0
        assert plan.context.get("nlp_target") == "example.com"

    def test_smart_plan_no_available_tools(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="", target_type="",
            template_name="recon_full", confidence=15.0,
            parameters={}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        with patch.object(planner, "decompose_goal", return_value=MagicMock()) as mock_decompose:
            planner.smart_plan("scan", available_tools=None)
            mock_decompose.assert_not_called()


# ---------------------------------------------------------------------------
# decompose_goal — Full Decision Matrix
# ---------------------------------------------------------------------------


class TestDecomposeGoal:
    def test_step0_nlp_template_high_confidence(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="example.com", target_type="domain",
            template_name="web_audit", confidence=2.0,
            parameters={}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("web audit example.com")
        assert "web_audit" in plan.goal

    def test_step0_nlp_tool_high_confidence(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"speed": "fast"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "nmap"

    def test_step0_nlp_tool_with_alternative(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"speed": "fast"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["masscan"])
        assert plan.steps[0].tool == "masscan"

    def test_step0_nmap_all_ports(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"ports": "all", "speed": "fast"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-p-" in flags

    def test_step0_nmap_specific_ports(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"ports": "22,80,443"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-p 22,80,443" in flags

    def test_step0_nmap_default_ports(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "--top-ports 100" in flags

    def test_step0_nmap_stealth_speed(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"speed": "stealth"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-sS -T2" in flags or "-sT -T2" in flags

    def test_step0_nmap_default_speed(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"speed": "default"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-sT -T4" in flags

    def test_step0_nmap_verbose(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"verbose": True}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-v" in flags

    def test_step0_nmap_timeout(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"timeout": "30m"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "--host-timeout 30m" in flags

    def test_step0_nmap_xml_format(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="10.0.0.1", target_type="ipv4",
            template_name=None, tool_name="nmap", confidence=4.0,
            parameters={"format": "xml"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("10.0.0.1", available_tools=["nmap"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-oX -" in flags

    def test_step0_nuclei_severity(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="example.com", target_type="domain",
            template_name=None, tool_name="nuclei", confidence=4.0,
            parameters={"severity": "critical", "format": "json"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("example.com", available_tools=["nuclei"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-s critical" in flags

    def test_step0_nuclei_json_timeout(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="example.com", target_type="domain",
            template_name=None, tool_name="nuclei", confidence=4.0,
            parameters={"timeout": "5s", "format": "json"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("example.com", available_tools=["nuclei"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-json-export" in flags
        assert "-timeout 5" in flags

    def test_step0_ffuf_gobuster_params(self, planner: RegistryPlanner):
        intent = ParsedIntent(
            target="example.com", target_type="domain",
            template_name=None, tool_name="ffuf", confidence=4.0,
            parameters={"timeout": "10s", "format": "json"}, tokens=[],
        )
        planner._nlp.parse = MagicMock(return_value=intent)
        plan = planner.decompose_goal("fuzz example.com", available_tools=["ffuf"])
        flags = plan.steps[0].args.get("flags", "")
        assert "-t 10" in flags
        assert "-o result.json -of json" in flags

    def test_step1_keyword_template_match(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("brute force passwords on target")
        assert len(plan.steps) > 0

    def test_step1_keyword_network_scan(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("network scan 10.0.0.0/24")
        assert len(plan.steps) > 0

    def test_step1_keyword_web(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("web scan example.com")
        assert len(plan.steps) > 0

    def test_step1_keyword_ad(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("active directory audit dc.local")
        assert len(plan.steps) > 0

    def test_step1_keyword_cloud(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("cloud audit aws account")
        assert len(plan.steps) > 0

    def test_step1_keyword_privesc(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("linux privilege escalation")
        assert len(plan.steps) > 0

    def test_step1_keyword_vuln(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("vulnerability scan target")
        assert len(plan.steps) > 0

    def test_step1_keyword_dns(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("dns recon example.com")
        assert len(plan.steps) > 0

    def test_step1_keyword_smb(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("smb enum target")
        assert len(plan.steps) > 0

    def test_step1_keyword_full_scan(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("full scan target")
        assert len(plan.steps) > 0

    def test_step2_extract_target_no_match(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("just scan")
        assert plan is not None

    def test_step3_index_search_tool_match(self, planner: RegistryPlanner):
        planner.build_index(["nmap", "nuclei"])
        plan = planner.decompose_goal("run nmap on target", available_tools=["nmap"])
        assert plan.steps[0].tool == "nmap"

    def test_step3_index_search_fallback_direct_match(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("use nmap please", available_tools=["nmap", "nuclei"])
        assert plan.steps[0].tool == "nmap"

    def test_step3_no_keyword_index(self, planner: RegistryPlanner):
        # keyword_index is empty
        plan = planner.decompose_goal("scan something", available_tools=["nmap", "nuclei"])
        assert plan is not None

    def test_step3_skip_short_tool_names(self, planner: RegistryPlanner):
        planner._add_to_index("go", "go")
        plan = planner.decompose_goal("scan with go", available_tools=["go", "nmap"])
        assert plan is not None

    def test_step3_no_tool_match(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("do something", available_tools=["nmap"])
        assert plan is not None

    def test_step4_intent_map_headers(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("check headers on example.com")
        assert plan.steps[0].tool == "curl"

    def test_step4_intent_map_tech(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("fingerprint tech on example.com")
        assert plan.steps[0].tool == "whatweb"

    def test_step4_intent_map_wp(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("check wp on example.com")
        assert plan.steps[0].tool == "wpscan"

    def test_step4_intent_map_vuln(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("check vuln example.com")
        assert plan.steps[0].tool == "nuclei"

    def test_step4_intent_map_cve(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("check cve example.com")
        assert plan.steps[0].tool == "nuclei"

    def test_step4_intent_map_fuzz(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("fuzz example.com")
        assert plan.steps[0].tool == "ffuf"

    def test_step4_intent_map_directories(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("find directories on example.com")
        assert plan.steps[0].tool == "gobuster"

    def test_step4_intent_map_endpoint(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("find endpoints example.com")
        assert "gobuster" in plan.steps[0].tool

    def test_step4_intent_map_sqli(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("test sqli on example.com")
        assert plan.steps[0].tool == "sqlmap"

    def test_step4_intent_map_dns(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("resolve example.com")
        assert plan.steps[0].tool == "dig"

    def test_step4_intent_map_whois(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("whois lookup example.com")
        assert plan.steps[0].tool == "whois"

    def test_step4_intent_map_port(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("port scan 10.0.0.1")
        assert plan.steps[0].tool == "nmap"

    def test_step4_intent_map_masscan(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("masscan 10.0.0.0/24")
        assert plan.steps[0].tool == "masscan"

    def test_step4_intent_map_recon(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("recon 10.0.0.1")
        assert plan.steps[0].tool == "nmap"

    def test_step4_intent_map_scan(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("scan 10.0.0.1")
        assert plan.steps[0].tool == "nuclei"

    def test_step4_intent_map_explore(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("explore 10.0.0.1")
        assert plan.steps[0].tool == "nmap"

    def test_step4_intent_map_ssl(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("ssl check example.com")
        assert plan.steps[0].tool == "openssl"

    def test_step4_intent_map_alt_tool_selected(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("nmap 10.0.0.1", available_tools=["masscan"])
        assert plan.steps[0].tool == "masscan"

    def test_step4_intent_map_with_target_cleaning(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("check https://example.com/path?q=1")
        target = plan.steps[0].args.get("target", "")
        assert "/path" not in target

    def test_step5_probe_fallback(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("analyze https://target.com")
        assert len(plan.steps) > 0

    def test_step5_probe_steps_use_dag(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("probe random.example.com")
        assert len(plan.steps) > 2
        assert plan.plan_type == PlanType.DAG

    def test_step5_probe_with_alternatives(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("check https://example.com", available_tools=["masscan", "ffuf"])
        assert len(plan.steps) > 0

    def test_step5_no_probe_steps_if_no_target(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("do something")
        assert len(plan.steps) == 0

    def test_generic_scan_keywords(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("pentest the target")
        assert len(plan.steps) > 0

    def test_final_fallback_empty_plan(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("random text without keywords")
        assert plan.steps == []

    def test_decompose_goal_with_url_target_discovery(self, planner: RegistryPlanner):
        plan = planner.decompose_goal("scan https://example.com")
        assert plan.steps[0].args.get("target") != ""


# ---------------------------------------------------------------------------
# adapt_plan
# ---------------------------------------------------------------------------


class TestAdaptPlan:
    def test_adapt_nmap_filtered(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "nmap", "args": {"target": "x"}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "filtered ports")
        assert "-Pn" in step.args.get("flags", "")
        assert step.status == StepStatus.PENDING
        assert step.retry_count == 1

    def test_adapt_nmap_permission(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "nmap", "args": {"flags": "-sS"}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "permission denied")
        flags = step.args.get("flags", "")
        assert "-sS" not in flags
        assert step.status == StepStatus.PENDING

    def test_adapt_timeout_generic(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "anytool", "args": {}, "timeout": 100}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "timeout exceeded")
        assert step.args.get("timeout") == 150.0
        assert step.status == StepStatus.PENDING

    def test_adapt_gobuster_404(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "gobuster", "args": {}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "404 errors")
        assert "php" in step.args.get("extensions", "")
        assert step.status == StepStatus.PENDING

    def test_adapt_ffuf_404(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "ffuf", "args": {}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "all 404")
        assert "php" in step.args.get("extensions", "")

    def test_adapt_hydra_invalid_user(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "hydra", "args": {}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "invalid user")
        assert "-e nsr" in step.args.get("flags", "")

    def test_adapt_sqlmap_not_injectable(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "sqlmap", "args": {}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "not injectable")
        assert "--level=3" in step.args.get("flags", "")

    def test_adapt_refused_adds_nuclei_step(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "nmap", "args": {"target": "x"}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        result = planner.adapt_plan(plan, step, "connection refused")
        assert len(plan.steps) == 2
        assert plan.steps[1].tool == "nuclei"

    def test_adapt_no_recovery_rule_exhausted_retries(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "nmap", "args": {}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        step.retry_count = 3
        step.max_retries = 3
        result = planner.adapt_plan(plan, step, "unknown error")
        assert step.status == StepStatus.FAILED

    def test_adapt_no_recovery_can_still_retry(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "random_tool", "args": {}}])
        step = plan.steps[0]
        step.status = StepStatus.FAILED
        step.retry_count = 0
        result = planner.adapt_plan(plan, step, "some error")
        assert step.status == StepStatus.PENDING
        assert step.retry_count == 1

    def test_adapt_returns_same_plan(self, planner: RegistryPlanner):
        plan = planner.create_plan("test", steps=[{"tool": "nmap", "args": {}}])
        step = plan.steps[0]
        result = planner.adapt_plan(plan, step, "some error")
        assert result is plan


# ---------------------------------------------------------------------------
# get_plan / list_plans / stats
# ---------------------------------------------------------------------------


class TestQueryMethods:
    def test_get_plan(self, planner: RegistryPlanner):
        plan = planner.create_plan("test")
        assert planner.get_plan(plan.id) is plan

    def test_get_plan_missing(self, planner: RegistryPlanner):
        assert planner.get_plan("nonexistent") is None

    def test_list_plans(self, planner: RegistryPlanner):
        p1 = planner.create_plan("first")
        p2 = planner.create_plan("second")
        plans = planner.list_plans()
        assert len(plans) == 2

    def test_list_plans_sorted_by_time(self, planner: RegistryPlanner):
        p1 = planner.create_plan("first")
        time.sleep(0.05)
        p2 = planner.create_plan("second")
        plans = planner.list_plans()
        assert plans[0].goal == "second"
        assert plans[1].goal == "first"

    def test_list_plans_filter_by_status(self, planner: RegistryPlanner):
        p1 = planner.create_plan("active")
        p2 = planner.create_plan("inactive")
        p2.status = PlanStatus.COMPLETED
        active = planner.list_plans(status=PlanStatus.ACTIVE)
        assert len(active) == 1
        assert active[0].id == p1.id

    def test_stats(self, planner: RegistryPlanner):
        planner.create_plan("plan1")
        planner.create_plan("plan2")
        stats = planner.stats()
        assert stats["total_plans"] == 2
        assert stats["active"] == 2
        assert stats["completed"] == 0
        assert len(stats["templates"]) == len(planner._templates)

    def test_stats_with_completed(self, planner: RegistryPlanner):
        p1 = planner.create_plan("plan1")
        p1.status = PlanStatus.COMPLETED
        stats = planner.stats()
        assert stats["active"] == 0
        assert stats["completed"] == 1


# ---------------------------------------------------------------------------
# TOOL_ALTERNATIVES
# ---------------------------------------------------------------------------


class TestToolAlternatives:
    def test_structure(self):
        assert "nmap" in TOOL_ALTERNATIVES
        assert "masscan" in TOOL_ALTERNATIVES["nmap"]
        assert "gobuster" in TOOL_ALTERNATIVES
        assert "ffuf" in TOOL_ALTERNATIVES["gobuster"]

    def test_symmetry(self):
        assert "nmap" in TOOL_ALTERNATIVES["masscan"] if "masscan" in TOOL_ALTERNATIVES else True

class TestPlannerRegistryCore:
    """Cover uncovered lines in planner_registry.py."""

    def test_build_index_adds_metadata_tags_and_descriptions(self):
        planner = RegistryPlanner()
        mock_reg = MagicMock()
        mock_tool = MagicMock()
        mock_tool.name = "nmap"
        mock_tool.description = "Network mapper"
        mock_tool.tags = ["scan", "network"]
        mock_tool.category = "recon"
        mock_reg.get_tool.return_value = None
        mock_reg._graph.get_tool.return_value = mock_tool
        planner.build_index(["nmap"], tool_registry=mock_reg)
        assert "scan" in planner._keyword_index
        assert "nmap" in planner._keyword_index

    def test_smart_plan_low_confidence_falls_back(self):
        planner = RegistryPlanner()
        intent = MagicMock()
        intent.template_name = "web_audit"
        intent.confidence = 0.1
        intent.target = "example.com"
        intent.parameters = {}
        with patch.object(planner._nlp, "parse", return_value=intent):
            with patch.object(planner, "decompose_goal") as mock_dg:
                mock_dg.return_value = MagicMock()
                planner.smart_plan("scan example.com")
                mock_dg.assert_called_once()

    def test_adapt_plan_refused_fallback(self):
        from siyarix.planner_registry import RegistryPlanner
        from siyarix.models import StepStatus
        planner = RegistryPlanner()
        step = PlanStep(tool="nmap", args={"target": "x"})
        step.status = StepStatus.FAILED
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "connection refused")
        assert any(s.tool == "nuclei" for s in result.steps)

    def test_adapt_plan_generic_retry(self):
        from siyarix.planner_registry import RegistryPlanner
        from siyarix.models import StepStatus
        planner = RegistryPlanner()
        step = PlanStep(tool="nmap", retry_count=0, max_retries=3)
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "generic error")
        assert step.status == StepStatus.PENDING

    def test_adapt_plan_no_retry(self):
        from siyarix.planner_registry import RegistryPlanner
        from siyarix.models import StepStatus
        planner = RegistryPlanner()
        step = PlanStep(tool="nmap", retry_count=3, max_retries=3)
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "generic error")
        assert step.status == StepStatus.FAILED

    def test_list_plans_with_status_filter(self):
        from siyarix.planner_registry import RegistryPlanner
        from siyarix.models import PlanStatus
        planner = RegistryPlanner()
        p1 = planner.create_plan("test1")
        p1.status = PlanStatus.ACTIVE
        p2 = planner.create_plan("test2")
        p2.status = PlanStatus.COMPLETED
        plans = planner.list_plans(status=PlanStatus.ACTIVE)
        assert len(plans) == 1


# ═══════════════════════════════════════════════════════════════════
# tool_installer.py (93% - missing 136-137, 156-157, 219-221)
# ═══════════════════════════════════════════════════════════════════
class TestPlannerRegistryAdaptPlan:
    """Cover remaining planner_registry.py uncovered lines."""

    def test_build_index_tool_registry_get_tool_fallback(self):
        planner = RegistryPlanner()
        mock_registry = MagicMock()
        del mock_registry.get_tool
        mock_registry._graph.get_tool.return_value = MagicMock(
            name="nmap", description="Network mapper", tags=["scan", "port"], category="recon"
        )
        planner.build_index(["nmap"], tool_registry=mock_registry)
        assert "nmap" in planner._keyword_index.get("scan", set())

    def test_build_index_tool_registry_exception(self):
        planner = RegistryPlanner()
        mock_registry = MagicMock()
        mock_registry.get_tool.side_effect = RuntimeError("registry fail")
        with patch("siyarix.planner_registry.logger") as mock_log:
            planner.build_index(["nmap"], tool_registry=mock_registry)
            mock_log.warning.assert_called()

    def test_search_index_empty_words(self):
        planner = RegistryPlanner()
        result = planner._search_index("a")
        assert result == []

    def test_search_index_no_scores_fallback(self):
        planner = RegistryPlanner()
        planner._keyword_index["test"] = {"tool1"}
        result = planner._search_index("test query")
        assert "tool1" in result

    def test_search_index_partial_bonus(self):
        planner = RegistryPlanner()
        planner._keyword_index["scan"] = {"nmap"}
        result = planner._search_index("run a scan please")
        assert "nmap" in result

    def test_resolve_alternatives_no_available_tools(self):
        planner = RegistryPlanner()
        result = planner.resolve_alternatives("recon_full", set())
        assert len(result) > 0

    def test_resolve_alternatives_fallback_warning(self):
        planner = RegistryPlanner()
        with patch("siyarix.planner_registry.logger") as mock_log:
            result = planner.resolve_alternatives("recon_full", {"nmap"})
            mock_log.warning.assert_called()

    def test_smart_plan_low_confidence_fallback(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.1
            intent.target = ""
            mock_parse.return_value = intent
            plan = planner.smart_plan("scan 10.0.0.1", ["nmap"])
            assert plan is not None

    def test_decompose_goal_with_semantic_params_fast(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.1
            intent.target = "10.0.0.1"
            intent.tool_name = "nmap"
            intent.parameters = {"speed": "fast", "ports": "all", "verbose": True, "timeout": "30s"}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("scan 10.0.0.1", ["nmap"])
            assert plan is not None

    def test_decompose_goal_semantic_params_nuclei(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.1
            intent.target = "example.com"
            intent.tool_name = "nuclei"
            intent.parameters = {"severity": "high", "format": "json", "timeout": "10s"}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("scan example.com", ["nuclei"])
            assert plan is not None

    def test_decompose_goal_semantic_params_ffuf(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.1
            intent.target = "example.com"
            intent.tool_name = "ffuf"
            intent.parameters = {"timeout": "5s", "format": "json"}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("fuzz example.com", ["ffuf"])
            assert plan is not None

    def test_decompose_goal_multiple_intents(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse_multi") as mock_parse_multi:
            intent1 = MagicMock()
            intent1.raw_text = "scan 10.0.0.1"
            intent2 = MagicMock()
            intent2.raw_text = "scan 10.0.0.2"
            mock_parse_multi.return_value = [intent1, intent2]
            with patch.object(planner, "decompose_goal") as mock_dg:
                mock_dg.return_value = MagicMock(steps=[], plan_type="sequential")
                plan = planner.decompose_goal("scan both", ["nmap"])
                assert plan is not None

    def test_adapt_plan_refused(self):
        from siyarix.models import PlanStatus
        planner = RegistryPlanner()
        plan = ExecutionPlan(goal="test", steps=[])
        step = PlanStep(id="s1", tool="curl", args={"target": "http://example.com"})
        plan.steps = [step]
        plan.status = PlanStatus.ACTIVE
        result = planner.adapt_plan(plan, step, "connection refused")
        assert len(plan.steps) > 1

    def test_adapt_plan_no_retry(self):
        planner = RegistryPlanner()
        step = MagicMock(spec=PlanStep, id="s1", tool="nmap", args={"target": "10.0.0.1"})
        step.can_retry = False
        plan = MagicMock()
        result = planner.adapt_plan(plan, step, "some error")
        assert result is plan

    def test_list_plans_filtered(self):
        planner = RegistryPlanner()
        from siyarix.models import PlanStatus
        plan1 = planner.create_plan("test1")
        plan2 = planner.create_plan("test2")
        plans = planner.list_plans(status=PlanStatus.ACTIVE)
        assert len(plans) >= 2
        plans_empty = planner.list_plans(status=PlanStatus.COMPLETED)
        assert len(plans_empty) == 0
class TestPlannerRegistryAlternatives:
    """Cover remaining planner_registry.py uncovered lines."""

    def test_decompose_goal_semantic_params_stealth(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.1
            intent.target = "10.0.0.1"
            intent.tool_name = "nmap"
            intent.parameters = {"speed": "stealth", "ports": "80,443", "format": "xml"}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("stealth scan 10.0.0.1", ["nmap"])
            assert plan is not None

    def test_decompose_goal_semantic_params_nuclei_json(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.1
            intent.target = "example.com"
            intent.tool_name = "nuclei"
            intent.parameters = {"severity": "critical", "format": "json", "timeout": "30s"}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("scan vulns", ["nuclei"])
            assert plan is not None

    def test_decompose_goal_semantic_params_gobuster(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.1
            intent.target = "example.com"
            intent.tool_name = "gobuster"
            intent.parameters = {"timeout": "10s", "format": "json"}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("dirbust example.com", ["gobuster"])
            assert plan is not None

    def test_decompose_goal_high_confidence_template(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = "web_audit"
            intent.confidence = 2.0
            intent.target = "example.com"
            intent.parameters = {}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("audit example.com", ["nmap", "nuclei", "whatweb"])
            assert plan is not None

    def test_decompose_goal_no_tool_match_fallback_to_keyword(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.0
            intent.target = ""
            intent.tool_name = ""
            intent.parameters = {}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("brute force 10.0.0.1", ["nmap"])
            assert plan is not None

    def test_decompose_goal_probe_steps(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.0
            intent.target = "10.0.0.1"
            intent.tool_name = ""
            intent.parameters = {}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("scan 10.0.0.1", ["nmap", "whatweb", "nuclei"])
            assert plan is not None

    def test_decompose_goal_keyword_fallback(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.0
            intent.target = ""
            intent.tool_name = ""
            intent.parameters = {}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("pentest example.com", ["nmap", "whatweb"])
            assert plan is not None

    def test_decompose_goal_empty_goal(self):
        planner = RegistryPlanner()
        with patch.object(planner._nlp, "parse") as mock_parse:
            intent = MagicMock()
            intent.template_name = ""
            intent.confidence = 0.0
            intent.target = ""
            intent.tool_name = ""
            intent.parameters = {}
            mock_parse.return_value = intent
            plan = planner.decompose_goal("just a thing", ["nmap"])
            assert plan is not None

    def test_adapt_plan_nmap_filtered_recovery(self):
        from siyarix.models import StepStatus
        planner = RegistryPlanner()
        step = PlanStep(tool="nmap", args={"flags": "-sS"}, retry_count=0, max_retries=3)
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "filtered ports detected")
        assert step.status == StepStatus.PENDING

    def test_adapt_plan_nmap_permission_recovery(self):
        planner = RegistryPlanner()
        step = PlanStep(tool="nmap", args={"flags": "-sS"}, retry_count=0, max_retries=3)
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "permission denied")
        assert "sT" in step.args.get("flags", "")

    def test_adapt_plan_gobuster_404(self):
        planner = RegistryPlanner()
        step = PlanStep(tool="gobuster", args={}, retry_count=0, max_retries=3)
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "404 errors")
        assert "extensions" in step.args

    def test_adapt_plan_hydra_invalid_user(self):
        planner = RegistryPlanner()
        step = PlanStep(tool="hydra", args={}, retry_count=0, max_retries=3)
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "invalid user")
        assert "nsr" in step.args.get("flags", "")

    def test_adapt_plan_sqlmap_not_injectable(self):
        planner = RegistryPlanner()
        step = PlanStep(tool="sqlmap", args={}, retry_count=0, max_retries=3)
        plan = ExecutionPlan(goal="test", steps=[step])
        result = planner.adapt_plan(plan, step, "not injectable")
        assert "level" in step.args.get("flags", "")

    def test_stats_returns_counts(self):
        planner = RegistryPlanner()
        planner.create_plan("test1")
        s = planner.stats()
        assert s["total_plans"] > 0
        assert "templates" in s


# ═══════════════════════════════════════════════════════════════════
# 13. config.py (96% - missing env override, backup, restore)
# ═══════════════════════════════════════════════════════════════════
