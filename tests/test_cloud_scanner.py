"""Tests for CloudScanner."""

from __future__ import annotations

import pytest
from siyarix.cloud_scanner import CloudScanner, CloudScanResult, CloudProvider
pytestmark = pytest.mark.cloud


class TestCloudScanner:
    @pytest.fixture
    def scanner(self):
        return CloudScanner()

    @pytest.mark.asyncio
    async def test_scan_aws(self, scanner):
        result = await scanner.scan_aws(account_id="123456789012")
        assert result.provider == CloudProvider.AWS
        assert len(result.findings) > 0
        assert result.target == "123456789012"

    @pytest.mark.asyncio
    async def test_scan_azure(self, scanner):
        result = await scanner.scan_azure(subscription_id="sub-123")
        assert result.provider == CloudProvider.AZURE
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_gcp(self, scanner):
        result = await scanner.scan_gcp(project_id="my-project")
        assert result.provider == CloudProvider.GCP
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_kubernetes(self, scanner):
        result = await scanner.scan_kubernetes(namespace="production")
        assert result.provider == CloudProvider.KUBERNETES
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_docker(self, scanner):
        result = await scanner.scan_docker(image_name="nginx:latest")
        assert result.provider == CloudProvider.DOCKER
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_by_provider(self, scanner):
        result = await scanner.scan_by_provider(CloudProvider.AWS, "test-account")
        assert result.provider == CloudProvider.AWS

    @pytest.mark.asyncio
    async def test_scan_by_provider_invalid(self, scanner):
        result = await scanner.scan_by_provider("invalid", "test")
        assert result is not None

    def test_history(self, scanner):
        assert len(scanner.get_history()) == 0

    @pytest.mark.asyncio
    async def test_summary(self, scanner):
        await scanner.scan_aws()
        summary = scanner.summary()
        assert summary["total_scans"] >= 1
        assert "aws" in summary["providers_scanned"]

    def test_scan_result_dataclass(self):
        result = CloudScanResult(provider=CloudProvider.AWS, target="test")
        assert result.provider == CloudProvider.AWS
        assert result.target == "test"
