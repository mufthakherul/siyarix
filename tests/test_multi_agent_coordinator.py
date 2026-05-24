import asyncio

from siyarix.agents.coordinator import CoordinatorAgent


class _FakeEngineResult:
    def __init__(self) -> None:
        self.success = True
        self.summary = {"success": 1}
        self.all_findings = [{"severity": "info"}]
        self.step_results = [object()]


class _FakeEngine:
    async def execute(self, instruction: str, interactive: bool, persist: bool):  # noqa: ARG002
        assert instruction
        return _FakeEngineResult()


def test_coordinator_dispatches_objective() -> None:
    coordinator = CoordinatorAgent(engine=_FakeEngine())  # type: ignore[arg-type]
    result = asyncio.run(coordinator.execute_objective("full recon and scan", target="example.com"))

    assert result["team"] == "siyarix-hybrid-team"
    assert result["target"] == "example.com"
    assert result["agents_used"] >= 5
    assert isinstance(result["results"], list)
