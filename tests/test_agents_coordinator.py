"""Tests for the Coordinator Agent."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from phalanx.agents.coordinator import CoordinatorAgent


class TestCoordinatorAgent:
    """Test suite for CoordinatorAgent."""

    @pytest.fixture
    def mock_engine(self):
        engine = MagicMock()
        engine.execute = AsyncMock(
            return_value=MagicMock(
                success=True,
                summary="test summary",
                all_findings=[],
                step_results=[],
                total_duration_ms=100.0,
            )
        )
        return engine

    @pytest.fixture
    def coordinator(self, mock_engine):
        return CoordinatorAgent(mock_engine)

    def test_initialization(self, coordinator):
        assert coordinator._team is not None
        assert len(coordinator._execution_history) == 0

    def test_register_default_agents(self, coordinator):
        agents = coordinator._team.list_agents()
        assert len(agents) >= 6  # 5 role agents + SOC + DFIR
        agent_names = [a.name for a in agents]
        assert "recon-1" in agent_names
        assert "scanner-1" in agent_names
        assert "exploit-1" in agent_names
        assert "soc-analyst-1" in agent_names
        assert "dfir-responder-1" in agent_names

    @pytest.mark.asyncio
    async def test_execute_objective_recon(self, coordinator):
        result = await coordinator.execute_objective("recon scan example.com")
        assert result["objective"] == "recon scan example.com"
        assert "recon" in result["phases_executed"]

    @pytest.mark.asyncio
    async def test_execute_objective_exploit(self, coordinator):
        result = await coordinator.execute_objective("exploit web app", target="example.com")
        assert "exploitation" in result["phases_executed"]

    @pytest.mark.asyncio
    async def test_execute_objective_default_phases(self, coordinator):
        result = await coordinator.execute_objective("check status")
        assert "recon" in result["phases_executed"]
        assert "scanning" in result["phases_executed"]

    def test_decompose_objective_recon(self, coordinator):
        phases = coordinator._decompose_objective("discover subdomains of example.com")
        assert "recon" in phases

    def test_decompose_objective_exploit(self, coordinator):
        phases = coordinator._decompose_objective("exploit and attack vulnerabilities")
        assert "exploitation" in phases

    def test_decompose_objective_report(self, coordinator):
        phases = coordinator._decompose_objective("generate report of findings")
        assert "reporting" in phases

    def test_decompose_objective_all(self, coordinator):
        phases = coordinator._decompose_objective("scan, exploit, and report")
        assert "scanning" in phases
        assert "exploitation" in phases
        assert "reporting" in phases

    def test_get_history_empty(self, coordinator):
        assert coordinator.get_history() == []

    @pytest.mark.asyncio
    async def test_get_history_after_execution(self, coordinator):
        await coordinator.execute_objective("scan example.com")
        history = coordinator.get_history()
        assert len(history) == 1
        assert history[0]["objective"] == "scan example.com"

    def test_team_property(self, coordinator):
        assert coordinator.team is coordinator._team

    def test_engine_property(self, coordinator, mock_engine):
        assert coordinator.engine is mock_engine
