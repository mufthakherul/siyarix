"""Tests for src/siyarix/playbook.py — 100% coverage."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest
import yaml

from siyarix.models import ExecutionPlan, PlanStep, PlanType
from siyarix.playbook import PlaybookEngine
from siyarix.workflow import WorkflowEngine


@pytest.fixture
def mock_workflow_engine() -> MagicMock:
    engine = MagicMock(spec=WorkflowEngine)
    engine.create_workflow = MagicMock()
    engine.run_workflow = AsyncMock()
    return engine


@pytest.fixture
def playbook_engine(mock_workflow_engine: MagicMock) -> PlaybookEngine:
    return PlaybookEngine(mock_workflow_engine)


# -- __init__ -----------------------------------------------------------------

def test_init_stores_workflow_engine(mock_workflow_engine: MagicMock) -> None:
    engine = PlaybookEngine(mock_workflow_engine)
    assert engine.workflow_engine is mock_workflow_engine


# -- load ---------------------------------------------------------------------

def test_load_valid_yaml(playbook_engine: PlaybookEngine, tmp_path: Path) -> None:
    playbook = {"steps": [{"tool": "nmap", "args": {"target": "example.com"}}]}
    path = tmp_path / "playbook.yaml"
    path.write_text(yaml.dump(playbook))
    result = playbook_engine.load(path)
    assert result == playbook


def test_load_file_not_found(playbook_engine: PlaybookEngine) -> None:
    with pytest.raises(FileNotFoundError):
        playbook_engine.load("/nonexistent/path.yaml")


def test_load_empty_file(playbook_engine: PlaybookEngine, tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("")
    with pytest.raises(ValueError, match="Playbook must be a YAML dictionary"):
        playbook_engine.load(path)


def test_load_non_dict_yaml(playbook_engine: PlaybookEngine, tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text(yaml.dump(["a", "b"]))
    with pytest.raises(ValueError, match="Playbook must be a YAML dictionary"):
        playbook_engine.load(path)


def test_load_missing_steps(playbook_engine: PlaybookEngine, tmp_path: Path) -> None:
    path = tmp_path / "no_steps.yaml"
    path.write_text(yaml.dump({"key": "value"}))
    with pytest.raises(ValueError, match="Playbook missing 'steps' section"):
        playbook_engine.load(path)


# -- _resolve_vars ------------------------------------------------------------

def test_resolve_vars_simple(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_vars("hello {{ name }}", {"name": "world"})
    assert result == "hello world"


def test_resolve_vars_env_var(playbook_engine: PlaybookEngine) -> None:
    with patch.dict(os.environ, {"MY_VAR": "env_value"}, clear=True):
        result = playbook_engine._resolve_vars("{{ env.MY_VAR }}", {})
    assert result == "env_value"


def test_resolve_vars_missing_var(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_vars("{{ missing }}", {})
    assert result == "{{ missing }}"


def test_resolve_vars_missing_env(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_vars("{{ env.NONEXISTENT }}", {})
    assert result == ""


def test_resolve_vars_nested_placeholders(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_vars(
        "{{ outer }}-{{ inner }}", {"outer": "a", "inner": "b"}
    )
    assert result == "a-b"


def test_resolve_vars_no_template(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_vars("plain text", {"x": "y"})
    assert result == "plain text"


def test_resolve_vars_with_whitespace(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_vars("{{  spaced  }}", {"spaced": "ok"})
    assert result == "ok"


# -- _resolve_dict ------------------------------------------------------------

def test_resolve_dict_dict(playbook_engine: PlaybookEngine) -> None:
    data = {"name": "{{ var }}", "static": "hello"}
    result = playbook_engine._resolve_dict(data, {"var": "world"})
    assert result == {"name": "world", "static": "hello"}


def test_resolve_dict_list(playbook_engine: PlaybookEngine) -> None:
    data = ["{{ a }}", "{{ b }}"]
    result = playbook_engine._resolve_dict(data, {"a": "1", "b": "2"})
    assert result == ["1", "2"]


def test_resolve_dict_string(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_dict("{{ x }}", {"x": "y"})
    assert result == "y"


def test_resolve_dict_nested(playbook_engine: PlaybookEngine) -> None:
    data = {"outer": {"inner": "{{ val }}"}}
    result = playbook_engine._resolve_dict(data, {"val": "deep"})
    assert result == {"outer": {"inner": "deep"}}


def test_resolve_dict_non_string(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_dict(42, {})
    assert result == 42


def test_resolve_dict_none(playbook_engine: PlaybookEngine) -> None:
    result = playbook_engine._resolve_dict(None, {})
    assert result is None


# -- create_plan --------------------------------------------------------------

def test_create_plan_basic(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {"tool": "nmap", "args": {"target": "example.com"}},
        ]
    }
    plan = playbook_engine.create_plan(data)
    assert isinstance(plan, ExecutionPlan)
    assert plan.plan_type == PlanType.DAG
    assert len(plan.steps) == 1
    assert plan.steps[0].tool == "nmap"


def test_create_plan_with_variables(playbook_engine: PlaybookEngine) -> None:
    data = {
        "vars": {"domain": "example.com"},
        "steps": [{"tool": "nmap", "args": {"target": "{{ domain }}"}}],
    }
    plan = playbook_engine.create_plan(data, variables={"extra": "val"})
    args = json.loads(plan.steps[0].command)
    assert args["target"] == "example.com"


def test_create_plan_vars_precedence(playbook_engine: PlaybookEngine) -> None:
    data = {
        "vars": {"host": "from_playbook"},
        "steps": [{"tool": "ping", "args": {"host": "{{ host }}"}}],
    }
    plan = playbook_engine.create_plan(data, variables={"host": "from_args"})
    args = json.loads(plan.steps[0].command)
    assert args["host"] == "from_args"


def test_create_plan_non_string_var(playbook_engine: PlaybookEngine) -> None:
    data = {
        "vars": {"count": 5},
        "steps": [{"tool": "ping", "args": {"count": "{{ count }}"}}],
    }
    plan = playbook_engine.create_plan(data)
    args = json.loads(plan.steps[0].command)
    assert args["count"] == "5"


def test_create_plan_var_non_string_with_resolve(playbook_engine: PlaybookEngine) -> None:
    data = {
        "vars": {"count": 5},
        "steps": [{"tool": "ping"}],
    }
    plan = playbook_engine.create_plan(data)
    assert json.loads(plan.steps[0].command) == {}


def test_create_plan_var_string_resolve(playbook_engine: PlaybookEngine) -> None:
    data = {
        "vars": {"target": "example.com"},
        "steps": [{"tool": "nmap", "args": {"host": "{{ target }}"}}],
    }
    plan = playbook_engine.create_plan(data)
    args = json.loads(plan.steps[0].command)
    assert args["host"] == "example.com"


def test_create_plan_agent_step(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {
                "type": "agent",
                "role": "analyst",
                "goal": "Analyze findings",
                "tool": "overridden",
            }
        ]
    }
    plan = playbook_engine.create_plan(data)
    step = plan.steps[0]
    assert step.tool == "_subagent"
    args = json.loads(step.command)
    assert args["role"] == "analyst"
    assert args["goal"] == "Analyze findings"


def test_create_plan_with_condition(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {"tool": "nmap", "if": "{{ condition_var }}", "args": {}},
        ]
    }
    plan = playbook_engine.create_plan(data)
    args = json.loads(plan.steps[0].command)
    assert args["_condition"] == "{{ condition_var }}"


def test_create_plan_with_retries(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {"tool": "nmap", "retries": 3, "args": {}},
        ]
    }
    plan = playbook_engine.create_plan(data)
    args = json.loads(plan.steps[0].command)
    assert args["_retries"] == 3


def test_create_plan_with_timeout(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {"tool": "nmap", "timeout": 30.0},
        ]
    }
    plan = playbook_engine.create_plan(data)
    assert plan.steps[0].timeout == 30.0


def test_create_plan_default_timeout(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {"tool": "nmap"},
        ]
    }
    plan = playbook_engine.create_plan(data)
    assert plan.steps[0].timeout == 600.0


def test_create_plan_empty_steps(playbook_engine: PlaybookEngine) -> None:
    data = {"steps": []}
    plan = playbook_engine.create_plan(data)
    assert len(plan.steps) == 0


def test_create_plan_missing_fields(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {"description": "Custom step"},
        ]
    }
    plan = playbook_engine.create_plan(data)
    step = plan.steps[0]
    assert step.id.startswith("step_")
    assert step.tool == ""
    assert step.description == "Custom step"
    assert json.loads(step.command) == {}
    assert step.dependencies == []


def test_create_plan_with_depends_on(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [
            {"id": "scan", "tool": "nmap"},
            {"id": "report", "tool": "echo", "depends_on": ["scan"]},
        ]
    }
    plan = playbook_engine.create_plan(data)
    assert plan.steps[1].dependencies == ["scan"]


def test_create_plan_without_variables(playbook_engine: PlaybookEngine) -> None:
    data = {
        "steps": [{"tool": "nmap"}],
    }
    plan = playbook_engine.create_plan(data)
    assert len(plan.steps) == 1


# -- execute ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_happy_path(playbook_engine: PlaybookEngine, tmp_path: Path) -> None:
    playbook = {"steps": [{"tool": "nmap", "args": {"target": "example.com"}}]}
    path = tmp_path / "playbook.yaml"
    path.write_text(yaml.dump(playbook))

    mock_wf = MagicMock()
    mock_wf.steps = []
    playbook_engine.workflow_engine.create_workflow.return_value = mock_wf
    playbook_engine.workflow_engine.run_workflow.return_value = "workflow_result"

    result = await playbook_engine.execute(path)

    assert result == "workflow_result"
    playbook_engine.workflow_engine.create_workflow.assert_called_once()
    playbook_engine.workflow_engine.run_workflow.assert_called_once_with(mock_wf)


@pytest.mark.asyncio
async def test_execute_with_variables(playbook_engine: PlaybookEngine, tmp_path: Path) -> None:
    playbook = {"steps": [{"tool": "nmap", "args": {"target": "{{ host }}"}}]}
    path = tmp_path / "playbook.yaml"
    path.write_text(yaml.dump(playbook))

    mock_wf = MagicMock()
    mock_wf.steps = []
    playbook_engine.workflow_engine.create_workflow.return_value = mock_wf
    playbook_engine.workflow_engine.run_workflow.return_value = {}

    await playbook_engine.execute(path, variables={"host": "scanme.org"})

    call_kwargs = playbook_engine.workflow_engine.create_workflow.call_args[1]
    assert len(call_kwargs["nodes"]) == 1
    node_args = json.loads(call_kwargs["nodes"][0]["args"]["command"])
    assert node_args["target"] == "scanme.org"


@pytest.mark.asyncio
async def test_execute_with_edges(playbook_engine: PlaybookEngine, tmp_path: Path) -> None:
    playbook = {
        "steps": [
            {"id": "s1", "tool": "nmap"},
            {"id": "s2", "tool": "nuclei", "depends_on": ["s1"]},
        ]
    }
    path = tmp_path / "playbook.yaml"
    path.write_text(yaml.dump(playbook))

    mock_wf = MagicMock()
    mock_wf.steps = []
    playbook_engine.workflow_engine.create_workflow.return_value = mock_wf
    playbook_engine.workflow_engine.run_workflow.return_value = {}

    await playbook_engine.execute(path)

    call_kwargs = playbook_engine.workflow_engine.create_workflow.call_args[1]
    assert call_kwargs["edges"] == [{"source": "s1", "target": "s2"}]


@pytest.mark.asyncio
async def test_execute_propagates_load_errors(playbook_engine: PlaybookEngine) -> None:
    with pytest.raises(FileNotFoundError):
        await playbook_engine.execute("/nonexistent/path.yaml")
