import asyncio

from phalanx.tool_executor import ToolExecutor
from phalanx.engine_types import StepResult, StepStatus
from phalanx.planner import ExecutionStep, StepType


class DummyResolver:
    def resolve(self, name, args):
        class R:
            is_safe = True
            path = "/bin/echo"
            warnings = []

        r = R()
        r.args = args
        return r


class DummyToolInfo:
    def __init__(self, name="echo"):
        self.name = name
        self.path = "/bin/echo"


class DummyResult:
    def __init__(self):
        self.stdout = "ok"
        self.stderr = ""
        self.exit_code = 0


async def fake_run_tool(path, args, timeout):
    await asyncio.sleep(0)
    return DummyResult()


def test_run_tool_step_basic():
    resolver = DummyResolver()
    tools = [DummyToolInfo()]
    executor = ToolExecutor(
        resolver=resolver, discovered_tools=tools, graph=None, run_tool_fn=fake_run_tool
    )

    step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="echo", args=["hello"])

    res = asyncio.run(executor.execute_step(step, interactive=False))
    assert isinstance(res, StepResult)
    assert res.status == StepStatus.SUCCESS
    assert "ok" in res.output
