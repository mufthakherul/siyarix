"""Tests for src/siyarix/threat_intel.py — 100% coverage."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import urllib.error
import urllib.request

from siyarix.threat_intel import (
    AlienVaultOTX,
    MITREAttackDB,
    NVDDatabase,
    ThreatIntelFeed,
    ThreatIntelManager,
    ThreatIntelProvider,
    intel_manager,
)


# -- ThreatIntelProvider -------------------------------------------------------


class TestThreatIntelProvider:
    def test_init_with_api_key(self) -> None:
        provider = ThreatIntelProvider(api_key="secret")
        assert provider.api_key == "secret"

    def test_init_without_api_key(self) -> None:
        provider = ThreatIntelProvider()
        assert provider.api_key is None

    def test_init_with_none(self) -> None:
        provider = ThreatIntelProvider(api_key=None)
        assert provider.api_key is None


# -- AlienVaultOTX -------------------------------------------------------------


class TestAlienVaultOTXInit:
    def test_init_with_env_key(self) -> None:
        with patch.dict(os.environ, {"ALIENVAULT_API_KEY": "env-key"}, clear=True):
            otx = AlienVaultOTX()
            assert otx.api_key == "env-key"

    def test_init_without_env_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            otx = AlienVaultOTX()
            assert otx.api_key is None


class TestAlienVaultOTXLookupIP:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        fake_response_data = {
            "pulse_info": {"count": 3},
            "reputation": 0,
        }
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps(fake_response_data).encode()
        fake_response.__enter__.return_value = fake_response

        with (
            patch.dict(os.environ, {"ALIENVAULT_API_KEY": "test-key"}, clear=True),
            patch.object(urllib.request, "urlopen", return_value=fake_response) as mock_urlopen,
        ):
            otx = AlienVaultOTX()
            result = await otx.lookup_ip("8.8.8.8")

        assert result["source"] == "AlienVault OTX"
        assert result["pulse_count"] == 3
        assert result["reputation"] == 0
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.headers.get("X-otx-api-key") == "test-key"

    @pytest.mark.asyncio
    async def test_success_no_api_key(self) -> None:
        fake_response_data = {"pulse_info": {"count": 0}, "reputation": 0}
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps(fake_response_data).encode()
        fake_response.__enter__.return_value = fake_response

        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(urllib.request, "urlopen", return_value=fake_response) as mock_urlopen,
        ):
            otx = AlienVaultOTX()
            result = await otx.lookup_ip("1.1.1.1")

        assert result["source"] == "AlienVault OTX"
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert "X-OTX-API-KEY" not in req.headers

    @pytest.mark.asyncio
    async def test_network_error(self) -> None:
        with (
            patch.dict(os.environ, {"ALIENVAULT_API_KEY": "key"}, clear=True),
            patch.object(urllib.request, "urlopen", side_effect=urllib.error.URLError("timeout")),
        ):
            otx = AlienVaultOTX()
            result = await otx.lookup_ip("8.8.8.8")

        assert result["source"] == "AlienVault OTX"
        assert "error" in result
        assert "timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_missing_pulse_info_fields(self) -> None:
        fake_response_data = {}
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps(fake_response_data).encode()
        fake_response.__enter__.return_value = fake_response

        with (
            patch.dict(os.environ, {"ALIENVAULT_API_KEY": "key"}, clear=True),
            patch.object(urllib.request, "urlopen", return_value=fake_response),
        ):
            otx = AlienVaultOTX()
            result = await otx.lookup_ip("8.8.8.8")

        assert result["pulse_count"] == 0
        assert result["reputation"] == 0


# -- NVDDatabase --------------------------------------------------------------


class TestNVDDatabase:
    @pytest.mark.asyncio
    async def test_success_with_cvssv31(self) -> None:
        fake_response_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"value": "Test vuln description"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    }
                }
            ]
        }
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps(fake_response_data).encode()
        fake_response.__enter__.return_value = fake_response

        with patch.object(urllib.request, "urlopen", return_value=fake_response) as mock_urlopen:
            nvd = NVDDatabase()
            result = await nvd.lookup_cve("CVE-2023-1234")

        assert result["source"] == "NVD"
        assert result["id"] == "CVE-2023-1234"
        assert result["description"] == "Test vuln description"
        assert result["base_score"] == 9.8
        mock_urlopen.assert_called_once()

    @pytest.mark.asyncio
    async def test_cve_not_found(self) -> None:
        fake_response_data = {"vulnerabilities": []}
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps(fake_response_data).encode()
        fake_response.__enter__.return_value = fake_response

        with patch.object(urllib.request, "urlopen", return_value=fake_response):
            nvd = NVDDatabase()
            result = await nvd.lookup_cve("CVE-9999-9999")

        assert result["source"] == "NVD"
        assert result["error"] == "CVE not found"

    @pytest.mark.asyncio
    async def test_network_error(self) -> None:
        with patch.object(
            urllib.request, "urlopen", side_effect=urllib.error.URLError("connection refused")
        ):
            nvd = NVDDatabase()
            result = await nvd.lookup_cve("CVE-2023-1234")

        assert result["source"] == "NVD"
        assert "error" in result
        assert "connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_no_cvss_metrics(self) -> None:
        fake_response_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"value": "No score"}],
                        "metrics": {},
                    }
                }
            ]
        }
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps(fake_response_data).encode()
        fake_response.__enter__.return_value = fake_response

        with patch.object(urllib.request, "urlopen", return_value=fake_response):
            nvd = NVDDatabase()
            result = await nvd.lookup_cve("CVE-2023-5678")

        assert result["base_score"] is None

    @pytest.mark.asyncio
    async def test_missing_descriptions(self) -> None:
        fake_response_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [],
                        "metrics": {},
                    }
                }
            ]
        }
        fake_response = MagicMock()
        fake_response.read.return_value = json.dumps(fake_response_data).encode()
        fake_response.__enter__.return_value = fake_response

        with patch.object(urllib.request, "urlopen", return_value=fake_response):
            nvd = NVDDatabase()
            with pytest.raises(IndexError):
                await nvd.lookup_cve("CVE-2023-9999")


# -- ThreatIntelManager --------------------------------------------------------


class TestThreatIntelManager:
    @pytest.mark.asyncio
    async def test_analyze_target_cve(self) -> None:
        manager = ThreatIntelManager()
        with patch.object(
            manager.nvd, "lookup_cve", AsyncMock(return_value={"source": "NVD"})
        ) as mock_nvd:
            result = await manager.analyze_target("CVE-2023-1234")
            assert result == {"source": "NVD"}
            mock_nvd.assert_called_once_with("CVE-2023-1234")

    @pytest.mark.asyncio
    async def test_analyze_target_ip(self) -> None:
        manager = ThreatIntelManager()
        with patch.object(
            manager.alienvault, "lookup_ip", AsyncMock(return_value={"source": "AlienVault OTX"})
        ) as mock_av:
            result = await manager.analyze_target("8.8.8.8")
            assert result == {"source": "AlienVault OTX"}
            mock_av.assert_called_once_with("8.8.8.8")

    @pytest.mark.asyncio
    async def test_analyze_target_cve_lowercase_not_routed(self) -> None:
        manager = ThreatIntelManager()
        with (
            patch.object(
                manager.alienvault,
                "lookup_ip",
                AsyncMock(return_value={"source": "AlienVault OTX"}),
            ),
        ):
            result = await manager.analyze_target("cve-2023-1234")
            assert result["source"] == "AlienVault OTX"

    def test_singleton(self) -> None:
        assert isinstance(intel_manager, ThreatIntelManager)
        assert isinstance(intel_manager.alienvault, AlienVaultOTX)
        assert isinstance(intel_manager.nvd, NVDDatabase)


# -- ThreatIntelFeed & MITREAttackDB -------------------------------------------


class TestThreatIntelFeed:
    def test_init_and_list_feeds(self) -> None:
        feed = ThreatIntelFeed()
        assert isinstance(feed, ThreatIntelFeed)
        feeds = feed.list_feeds()
        assert len(feeds) >= 4
        names = [f["name"] for f in feeds]
        assert "AlienVault OTX" in names
        assert "National Vulnerability Database (NVD)" in names
        assert "MITRE ATT&CK Enterprise" in names

    def test_query_cve_found(self) -> None:
        feed = ThreatIntelFeed()
        data = feed.query_cve("CVE-2021-44228")
        assert data["id"] == "CVE-2021-44228"
        assert data["name"] == "Log4Shell"
        assert data["base_score"] == 10.0
        assert data["severity"] == "CRITICAL"
        assert data["mitre_technique"] == "T1190"

    def test_query_cve_lowercase(self) -> None:
        feed = ThreatIntelFeed()
        data = feed.query_cve("cve-2023-34362")
        assert data["id"] == "CVE-2023-34362"
        assert "MOVEit" in data["name"]

    def test_query_cve_not_found(self) -> None:
        feed = ThreatIntelFeed()
        data = feed.query_cve("CVE-1990-0001")
        assert data == {}

    def test_search_cve(self) -> None:
        feed = ThreatIntelFeed()
        results = feed.search("Outlook")
        assert len(results) >= 1
        assert any(r["id"] == "CVE-2024-21413" for r in results)

    def test_search_empty_and_not_found(self) -> None:
        feed = ThreatIntelFeed()
        assert feed.search("") == []
        assert feed.search("completely_unknown_token_xyz") == []

    def test_add_and_search_custom_indicator(self) -> None:
        feed = ThreatIntelFeed()
        feed.add_indicator("ip", "198.51.100.23", severity="high", description="C2 beacon IP")
        matches = feed.search("198.51.100.23")
        assert len(matches) == 1
        assert matches[0]["type"] == "ip"
        assert matches[0]["value"] == "198.51.100.23"


class TestMITREAttackDB:
    def test_init_and_list_tactics(self) -> None:
        db = MITREAttackDB()
        assert isinstance(db, MITREAttackDB)
        tactics = db.list_tactics()
        assert len(tactics) == 14
        tactic_ids = [t["id"] for t in tactics]
        assert "TA0001" in tactic_ids
        assert "TA0002" in tactic_ids

    def test_list_techniques(self) -> None:
        db = MITREAttackDB()
        techniques = db.list_techniques()
        assert len(techniques) >= 15
        for t in techniques:
            assert "id" in t
            assert "name" in t
            assert "tactic" in t

    def test_query_technique_direct_and_case_insensitive(self) -> None:
        db = MITREAttackDB()
        t1059 = db.query_technique("T1059")
        assert t1059["id"] == "T1059"
        assert t1059["name"] == "Command and Scripting Interpreter"
        assert t1059["tactic"] == "Execution"

        t1059_lower = db.query_technique("t1059")
        assert t1059_lower["name"] == "Command and Scripting Interpreter"

    def test_query_technique_subtechnique(self) -> None:
        db = MITREAttackDB()
        sub = db.query_technique("T1059.001")
        assert sub["id"] == "T1059.001"
        assert sub["name"] == "Command and Scripting Interpreter"

    def test_query_technique_not_found(self) -> None:
        db = MITREAttackDB()
        assert db.query_technique("T9999") == {}

    def test_search_techniques(self) -> None:
        db = MITREAttackDB()
        results = db.search("Phishing")
        assert any(r["id"] == "T1566" for r in results)

        tactic_results = db.search("Persistence")
        assert len(tactic_results) >= 2

        assert db.search("") == []
        assert db.search("nonexistent_technique_xyz") == []

    def test_map_finding(self) -> None:
        db = MITREAttackDB()
        mapped = db.map_finding("Detected SQL injection vulnerability via sqlmap")
        technique_ids = [m["id"] for m in mapped]
        assert "T1190" in technique_ids

        mapped_recon = db.map_finding("Active port scan discovered open ports")
        technique_ids_recon = [m["id"] for m in mapped_recon]
        assert "T1046" in technique_ids_recon

        mapped_empty = db.map_finding("Normal user logged in cleanly")
        assert mapped_empty == []


@pytest.mark.asyncio
async def test_threat_intel_handler_integration() -> None:
    from siyarix.internal_tools import make_threat_intel_handler

    handler = make_threat_intel_handler()

    # CVE lookup integration
    cve_res = await handler(action="cve_lookup", query="CVE-2021-44228")
    assert cve_res["status"] == "success"
    cve_data = json.loads(cve_res["output"])
    assert cve_data["cve_data"]["name"] == "Log4Shell"

    # MITRE lookup integration
    mitre_res = await handler(action="mitre_lookup", query="T1059")
    assert mitre_res["status"] == "success"
    mitre_data = json.loads(mitre_res["output"])
    assert mitre_data["mitre_data"]["name"] == "Command and Scripting Interpreter"
