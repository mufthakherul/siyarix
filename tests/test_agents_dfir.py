"""Tests for the DFIR Agent."""

from __future__ import annotations

import pytest

from siyarix.agents.dfir_agent import DFIRAgent


class TestDFIRAgent:
    """Test suite for DFIRAgent."""

    @pytest.fixture
    def agent(self):
        return DFIRAgent()

    def test_agent_initialization(self, agent):
        assert agent.name == "dfir-responder-1"
        assert agent.role == "dfir"
        assert len(agent.tools) > 0
        assert agent.total_iocs == 0

    @pytest.mark.asyncio
    async def test_gather_evidence_memory(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "victim-pc", "evidence_type": "memory"}
        )
        assert result["evidence_type"] == "memory"
        assert result["case_id"].startswith("DFIR-")
        assert result["collected_artifacts"] > 0

    @pytest.mark.asyncio
    async def test_gather_evidence_disk(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "victim-pc", "evidence_type": "disk"}
        )
        assert result["evidence_type"] == "disk"
        assert result["collected_artifacts"] > 0

    @pytest.mark.asyncio
    async def test_gather_evidence_network(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "10.0.0.1", "evidence_type": "network"}
        )
        assert result["evidence_type"] == "network"
        assert result["collected_artifacts"] > 0

    @pytest.mark.asyncio
    async def test_gather_evidence_log(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "syslog-server", "evidence_type": "log"}
        )
        assert result["evidence_type"] == "log"
        assert result["collected_artifacts"] > 0

    @pytest.mark.asyncio
    async def test_timeline_generation(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "victim-pc", "evidence_type": "memory"}
        )
        assert result["timeline_events"] > 0
        for event in result["timeline"][:5]:
            assert "timestamp" in event
            assert "event" in event
            assert "tool" in event

    @pytest.mark.asyncio
    async def test_ioc_extraction(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "victim-pc", "evidence_type": "memory"}
        )
        assert "ioc_matches" in result
        assert result["iocs_extracted"] >= 0

    @pytest.mark.asyncio
    async def test_chain_of_custody(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "victim-pc", "evidence_type": "memory"}
        )
        coc = result["chain_of_custody"]
        assert coc["case_officer"] == "DFIR Agent (automated)"
        assert coc["status"] == "preserved"
        assert coc["collection_method"] == "Automated forensic acquisition"

    @pytest.mark.asyncio
    async def test_recommended_next_steps_with_iocs(self, agent):
        result = await agent._gather_evidence(
            "", {"target": "victim-pc", "evidence_type": "memory"}
        )
        assert "Investigate" in result["recommended_next_steps"]

    @pytest.mark.asyncio
    async def test_case_summary(self, agent):
        await agent._gather_evidence("", {"target": "pc-1", "evidence_type": "memory"})
        await agent._gather_evidence("", {"target": "pc-2", "evidence_type": "disk"})
        summary = agent.get_case_summary()
        assert len(summary) == 2
        assert summary[0]["target"] == "pc-1"
        assert summary[1]["target"] == "pc-2"

    def test_recommend_next_with_iocs(self, agent):
        recommendation = agent._recommend_next(
            "target", "memory", [{"type": "ip", "value": "1.2.3.4"}]
        )
        assert "IOC(s)" in recommendation

    def test_recommend_next_no_iocs_memory(self, agent):
        recommendation = agent._recommend_next("target", "memory", [])
        assert "disk forensics" in recommendation

    def test_recommend_next_no_iocs(self, agent):
        recommendation = agent._recommend_next("target", "network", [])
        assert "deeper analysis" in recommendation
