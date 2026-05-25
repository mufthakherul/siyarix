"""Tests for MultiModelEnsemble."""

from __future__ import annotations

import pytest
pytestmark = pytest.mark.ensemble
from phalanx.multi_model_ensemble import MultiModelEnsemble, EnsembleResult, ModelResponse


class TestMultiModelEnsemble:
    @pytest.fixture
    def ensemble(self):
        return MultiModelEnsemble()

    def test_initial_state(self, ensemble):
        assert len(ensemble.available_providers()) == 0

    def _make_provider(self, response: str):
        def provider(task: str) -> str:
            return response

        return provider

    def test_register_provider(self, ensemble):
        provider = self._make_provider("nmap -sV target")
        ensemble.register_provider("openai", provider)
        assert "openai" in ensemble.available_providers()

    @pytest.mark.asyncio
    async def test_plan_no_providers(self, ensemble):
        result = await ensemble.plan("scan target")
        assert "No providers available" in result.selection_reason

    @pytest.mark.asyncio
    async def test_plan_with_providers(self, ensemble):
        ensemble.register_provider("provider1", self._make_provider("nmap -sV target"))
        ensemble.register_provider("provider2", self._make_provider("nuclei -u target"))
        result = await ensemble.plan("scan target")
        assert isinstance(result, EnsembleResult)
        assert len(result.responses) == 2

    @pytest.mark.asyncio
    async def test_plan_with_async_providers(self, ensemble):
        import asyncio

        async def async_provider(task):
            await asyncio.sleep(0.01)
            return "nmap -sV target"

        ensemble.register_provider("async-p", async_provider)
        result = await ensemble.plan("scan target")
        assert len(result.responses) == 1

    @pytest.mark.asyncio
    async def test_consensus_calculation(self, ensemble):
        ensemble.register_provider("p1", self._make_provider("nmap target"))
        ensemble.register_provider("p2", self._make_provider("nmap target"))
        result = await ensemble.plan("scan")
        assert result.consensus_level > 0.5

    def test_select_providers_for_task(self, ensemble):
        providers = ensemble.select_providers_for_task("simple task", complexity="simple")
        assert isinstance(providers, list)

    @pytest.mark.asyncio
    async def test_history(self, ensemble):
        ensemble.register_provider("p", self._make_provider("nmap target"))
        await ensemble.plan("scan")
        assert len(ensemble.get_history()) == 1

    def test_summary(self, ensemble):
        summary = ensemble.summary()
        assert summary["registered_providers"] == 0

    def test_model_response_dataclass(self):
        resp = ModelResponse(model_name="test", provider="test", plan="nmap -sV", confidence=0.9)
        assert resp.model_name == "test"
        assert resp.confidence == 0.9

    def test_ensemble_result_dataclass(self):
        result = EnsembleResult(task="scan", selection_reason="test")
        assert result.task == "scan"
