import pytest
from unittest.mock import MagicMock, AsyncMock
from siyarix.planner_autonomous import AutonomousPlanner

@pytest.fixture
def mock_session():
    session = MagicMock()
    session.target = "127.0.0.1"
    session.mode = "integrated"
    session.context = {}
    return session

@pytest.fixture
def planner():
    return AutonomousPlanner()

def test_planner_init(planner):
    assert planner._plans == {}
    assert planner.session_initialised is False

def test_create_plan(planner):
    steps_def = [
        {"tool": "nmap", "description": "scan", "args": {"t": "1"}},
        {"tool": "curl", "description": "fetch"}
    ]
    plan = planner.create_plan(
        goal="Test plan",
        steps=steps_def
    )
    assert len(plan.steps) == 2
    assert plan.steps[0].tool == "nmap"

def test_list_plans(planner):
    p1 = planner.create_plan("Test 1", steps=[])
    p2 = planner.create_plan("Test 2", steps=[])
    
    assert len(planner.list_plans()) == 2
    assert planner.get_plan(p1.id) is not None
    assert planner.get_plan("nonexistent") is None

def test_build_platform_context(planner):
    ctx = planner._build_platform_context()
    assert "Running on:" in ctx
    assert "Shell:" in ctx

@pytest.mark.asyncio
async def test_plan(planner):
    llm_call = AsyncMock(return_value={"tasks": [{"id": "t1", "tool": "raw", "command": "echo 'test'"}]})
    
    planner.reset_session()
    plan = await planner.plan("Do a simple echo", llm_call=llm_call)
    assert plan is not None
    assert planner.session_initialised is True
    
    plan2 = await planner.plan("Do another echo", llm_call=llm_call)
    assert plan2 is not None

def test_parse_llm_response_error(planner):
    assert planner._parse_llm_response("Not JSON") is None

def test_stats(planner):
    planner.create_plan("Test 1", steps=[])
    s = planner.stats()
    assert "total_plans" in s
    assert s["total_plans"] == 1
    assert "active" in s
