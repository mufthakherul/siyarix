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
            patch.object(
                urllib.request, "urlopen", side_effect=urllib.error.URLError("timeout")
            ),
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
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
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
        with patch.object(manager.nvd, "lookup_cve", AsyncMock(return_value={"source": "NVD"})) as mock_nvd:
            result = await manager.analyze_target("CVE-2023-1234")
            assert result == {"source": "NVD"}
            mock_nvd.assert_called_once_with("CVE-2023-1234")

    @pytest.mark.asyncio
    async def test_analyze_target_ip(self) -> None:
        manager = ThreatIntelManager()
        with patch.object(manager.alienvault, "lookup_ip", AsyncMock(return_value={"source": "AlienVault OTX"})) as mock_av:
            result = await manager.analyze_target("8.8.8.8")
            assert result == {"source": "AlienVault OTX"}
            mock_av.assert_called_once_with("8.8.8.8")

    @pytest.mark.asyncio
    async def test_analyze_target_cve_lowercase_not_routed(self) -> None:
        manager = ThreatIntelManager()
        with (
            patch.object(manager.alienvault, "lookup_ip", AsyncMock(return_value={"source": "AlienVault OTX"})),
        ):
            result = await manager.analyze_target("cve-2023-1234")
            assert result["source"] == "AlienVault OTX"

    def test_singleton(self) -> None:
        assert isinstance(intel_manager, ThreatIntelManager)
        assert isinstance(intel_manager.alienvault, AlienVaultOTX)
        assert isinstance(intel_manager.nvd, NVDDatabase)


# -- Stub classes --------------------------------------------------------------

class TestStubs:
    def test_threat_intel_feed(self) -> None:
        feed = ThreatIntelFeed()
        assert isinstance(feed, ThreatIntelFeed)

    def test_mitre_attack_db(self) -> None:
        db = MITREAttackDB()
        assert isinstance(db, MITREAttackDB)
