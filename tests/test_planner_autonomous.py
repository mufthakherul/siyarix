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
        {"tool": "curl", "description": "fetch"},
    ]
    plan = planner.create_plan(goal="Test plan", steps=steps_def)
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
    llm_call = AsyncMock(
        return_value={"tasks": [{"id": "t1", "tool": "raw", "command": "echo 'test'"}]}
    )

    planner.reset_session()
    plan = await planner.plan("Do a simple echo", llm_call=llm_call)
    assert plan is not None
    assert planner.session_initialised is True

    plan2 = await planner.plan("Do another echo", llm_call=llm_call)
    assert plan2 is not None


def test_parse_llm_response_error(planner):
    result = planner._parse_llm_response("Not JSON")
    assert isinstance(result, dict)
    assert result.get("needs_tools") is False


def test_stats(planner):
    planner.create_plan("Test 1", steps=[])
    s = planner.stats()
    assert "total_plans" in s
    assert s["total_plans"] == 1
    assert "active" in s


def test_plan_validator_deduplication(planner):
    steps_def = [
        {"tool": "nmap", "command": "nmap -sT 10.0.0.1", "description": "scan 1"},
        {"tool": "nmap", "command": "nmap -sT 10.0.0.1", "description": "scan duplicate"},
        {"tool": "curl", "command": "curl http://10.0.0.1", "description": "web probe"},
    ]
    plan = planner.create_plan(goal="Dedup test", steps=steps_def)
    assert len(plan.steps) == 2
    assert plan.steps[0].command == "nmap -sT 10.0.0.1"
    assert plan.steps[1].command == "curl http://10.0.0.1"


def test_plan_validator_dangerous_command():
    from siyarix.planner_autonomous import PlanValidator
    from siyarix.models import PlanStep

    dangerous_step = PlanStep(tool="bash", command="rm -rf /")
    validated = PlanValidator.validate_and_sanitize_step(dangerous_step)
    assert "SECURITY POLICY" in validated.command
    assert validated.metadata.get("blocked_dangerous") is True


def test_plan_validator_windows_sanitization():
    from siyarix.planner_autonomous import PlanValidator
    from siyarix.models import PlanStep

    win_step = PlanStep(tool="nmap", command="sudo nmap -sS 192.168.1.1")
    validated = PlanValidator.validate_and_sanitize_step(win_step, platform_system="Windows")
    assert "sudo" not in validated.command
    assert "-sT -Pn" in validated.command


def test_plan_validator_thread_clamping():
    from siyarix.planner_autonomous import PlanValidator
    from siyarix.models import PlanStep

    step = PlanStep(tool="gobuster", command="gobuster dir -u http://target -w list.txt -t 200")
    validated = PlanValidator.validate_and_sanitize_step(step)
    assert "-t 64" in validated.command


def test_plan_validator_execution_waves():
    from siyarix.planner_autonomous import PlanValidator
    from siyarix.models import PlanStep

    s1 = PlanStep(id="s1", tool="nmap", command="nmap target")
    s2 = PlanStep(id="s2", tool="nikto", command="nikto target", dependencies=["s1"])
    s3 = PlanStep(id="s3", tool="whatweb", command="whatweb target", dependencies=["s1"])
    s4 = PlanStep(id="s4", tool="report", command="report", dependencies=["s2", "s3"])

    waves = PlanValidator.compute_execution_waves([s1, s2, s3, s4])
    assert len(waves) == 3
    assert [s.id for s in waves[0]] == ["s1"]
    assert sorted([s.id for s in waves[1]]) == ["s2", "s3"]
    assert [s.id for s in waves[2]] == ["s4"]


def test_adapt_plan_nmap_permission_recovery(planner):
    from siyarix.models import StepStatus

    plan = planner.create_plan(
        goal="Port scan",
        steps=[{"tool": "nmap", "command": "nmap -sS 10.0.0.1", "description": "SYN scan"}],
    )
    failed_step = plan.steps[0]
    adapted = planner.adapt_plan_sync(
        plan, failed_step, error="Operation not permitted, requires root privileges"
    )

    assert "-sT" in failed_step.command
    assert "-Pn" in failed_step.command
    assert failed_step.status == StepStatus.PENDING
    assert failed_step.retry_count == 1


def test_adapt_plan_missing_binary_recovery(planner):
    from siyarix.models import StepStatus

    plan = planner.create_plan(
        goal="Web scan",
        steps=[{"tool": "nikto", "command": "nikto -h 10.0.0.1", "description": "Nikto scan"}],
    )
    failed_step = plan.steps[0]
    adapted = planner.adapt_plan_sync(plan, failed_step, error="nikto: command not found")

    assert failed_step.status == StepStatus.SKIPPED
    assert len(adapted.steps) == 2
    assert adapted.steps[1].tool == "curl"
