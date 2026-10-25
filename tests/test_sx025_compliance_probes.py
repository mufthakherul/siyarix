# SPDX-License-Identifier: AGPL-3.0-or-later
"""SX-025: compliance engine evaluates local probes; others stay NOT_EVALUATED."""

from __future__ import annotations

import pytest

from siyarix.compliance import ComplianceCheck, ComplianceEngine


@pytest.mark.asyncio
async def test_mapped_only_control_stays_not_evaluated() -> None:
    result = await ComplianceCheck("cc1.1", "example.com").run()
    assert result.status == "NOT_EVALUATED"
    assert result.evidence_data.get("evaluated") is False


@pytest.mark.asyncio
async def test_access_gate_probe_pass_when_not_preauthorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SIYARIX_PREAUTHORIZED", raising=False)
    result = await ComplianceCheck("cc6.1", "example.com").run()
    assert result.status == "PASS"
    assert result.evidence_data.get("evaluated") is True


@pytest.mark.asyncio
async def test_access_gate_probe_fail_when_preauthorized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIYARIX_PREAUTHORIZED", "1")
    result = await ComplianceCheck("AC-3", "example.com").run()
    assert result.status == "FAIL"


@pytest.mark.asyncio
async def test_soc2_assessment_has_mixed_statuses(tmp_path) -> None:
    engine = ComplianceEngine(base_dir=tmp_path / "evidence")
    report = await engine.run_assessment("SOC2", "example.com")
    statuses = {r.check_id: r.status for r in report.results}
    assert statuses["cc1.1"] == "NOT_EVALUATED"
    assert statuses["cc6.1"] in {"PASS", "FAIL"}
    assert statuses["cc6.2"] in {"PASS", "FAIL"}
    summary = report.summary()
    assert summary["NOT_EVALUATED"] >= 1
    data = report.to_json()
    assert "disclaimer" in data
    assert data["summary"]["NOT_EVALUATED"] >= 1
