"""Tests for the SOC Agent."""

from __future__ import annotations

import pytest

from phalanx.agents.soc_agent import SOCAgent


class TestSOCAgent:
    """Test suite for SOCAgent."""

    @pytest.fixture
    def agent(self):
        return SOCAgent()

    def test_agent_initialization(self, agent):
        assert agent.name == "soc-analyst-1"
        assert agent.role == "soc"
        assert len(agent.tools) > 0

    @pytest.mark.asyncio
    async def test_analyze_logs_no_anomalies(self, agent):
        result = await agent._analyze_logs(
            "", {"target": "test-system", "logs": "normal log entry"}
        )
        assert result["anomalies_detected"] == 0
        assert result["threat_level"] == "LOW"

    @pytest.mark.asyncio
    async def test_analyze_logs_failed_login(self, agent):
        logs = "\n".join(["failed login attempt from 192.168.1.100"] * 6)
        result = await agent._analyze_logs("", {"target": "test-system", "logs": logs})
        assert result["anomalies_detected"] >= 1
        assert any(a["rule"] == "failed_login" for a in result["anomalies"])

    @pytest.mark.asyncio
    async def test_analyze_logs_malware_detected(self, agent):
        logs = "\n".join(["malware detected in /tmp/evil.exe"] * 2)
        result = await agent._analyze_logs("", {"target": "test-system", "logs": logs})
        assert result["anomalies_detected"] >= 1
        assert any(a["rule"] == "malware_detected" for a in result["anomalies"])

    @pytest.mark.asyncio
    async def test_analyze_logs_webshell(self, agent):
        logs = "\n".join(["webshell activity: eval(base64_decode($_POST))"] * 2)
        result = await agent._analyze_logs("", {"target": "web-server", "logs": logs})
        assert result["anomalies_detected"] >= 1
        assert any(a["rule"] == "webshell" for a in result["anomalies"])

    @pytest.mark.asyncio
    async def test_triage_generation(self, agent):
        logs = "\n".join(["failed login attempt"] * 6 + ["malware detected"] * 2)
        result = await agent._analyze_logs("", {"target": "test-system", "logs": logs})
        assert result["tickets_generated"] > 0
        for ticket in result["triage_tickets"]:
            assert "ticket_id" in ticket
            assert "severity" in ticket
            assert "status" in ticket

    @pytest.mark.asyncio
    async def test_mitre_mapping(self, agent):
        logs = "\n".join(["failed login attempt"] * 6 + ["malware detected"] * 2)
        result = await agent._analyze_logs("", {"target": "test-system", "logs": logs})
        assert len(result["mitre_attack_mappings"]) > 0
        for mapping in result["mitre_attack_mappings"]:
            assert "attack_id" in mapping
            assert "technique" in mapping
            assert "tactic" in mapping

    @pytest.mark.asyncio
    async def test_threat_level_critical(self, agent):
        logs = "\n".join(["malware detected in system"] * 2)
        result = await agent._analyze_logs("", {"target": "test-system", "logs": logs})
        assert result["threat_level"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_threat_level_high(self, agent):
        logs = "\n".join(["privilege escalation attempt detected"] * 4)
        result = await agent._analyze_logs("", {"target": "test-system", "logs": logs})
        assert result["threat_level"] == "HIGH"

    @pytest.mark.asyncio
    async def test_threat_level_medium(self, agent):
        logs = "\n".join(["failed login attempt"] * 10)
        result = await agent._analyze_logs("", {"target": "test-system", "logs": logs})
        assert result["threat_level"] == "MEDIUM"

    def test_detect_anomalies_empty(self, agent):
        anomalies = agent._detect_anomalies("", "test")
        assert anomalies == []

    def test_action_for_severity(self, agent):
        assert "Immediate containment" in agent._action_for_severity("critical")
        assert "Escalate" in agent._action_for_severity("high")
        assert "Investigate" in agent._action_for_severity("medium")
        assert "periodic review" in agent._action_for_severity("low")

    def test_assess_threat_level_empty(self, agent):
        assert agent._assess_threat_level([]) == "LOW"
