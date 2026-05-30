# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.permission_gate — permission gate."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from siyarix.permission_gate import GateResult, PermissionGate


class TestGateResult:
    def test_defaults(self) -> None:
        r = GateResult(allowed=False, stage="syntax")
        assert r.allowed is False
        assert r.stage == "syntax"
        assert r.reason == ""
        assert r.tool == ""
        assert r.command == ""
        assert r.requires_review is False


class TestPermissionGate:
    def test_empty_command_returns_syntax_block(self) -> None:
        gate = PermissionGate()
        result = gate.check("")
        assert result.allowed is False
        assert result.stage == "syntax"
        assert "Empty" in result.reason

    def test_whitespace_command_returns_syntax_block(self) -> None:
        gate = PermissionGate()
        result = gate.check("   ")
        assert result.allowed is False
        assert result.stage == "syntax"

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_critical_danger_returns_forbidden(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(
            severity="critical", reasons=["rm -rf detected"]
        )
        gate = PermissionGate()
        result = gate.check("rm -rf /")
        assert result.allowed is False
        assert result.stage == "forbidden"
        assert "Destructive" in result.reason

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_high_danger_returns_review(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(
            severity="high", reasons=["shutdown detected"]
        )
        gate = PermissionGate()
        result = gate.check("shutdown -h now")
        assert result.allowed is True
        assert result.stage == "review"
        assert result.requires_review is True

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_medium_danger_returns_review(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(
            severity="medium", reasons=["rm detected"]
        )
        gate = PermissionGate()
        result = gate.check("rm file.txt")
        assert result.allowed is True
        assert result.stage == "review"
        assert result.requires_review is True

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_safe_command_returns_approved(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(
            severity="safe", reasons=[]
        )
        gate = PermissionGate()
        result = gate.check("ls -la")
        assert result.allowed is True
        assert result.stage == "approved"

    @pytest.mark.skip(reason="persona engine deferred to v2.0")
    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_persona_acl_allows_tool(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])

        mock_acl = MagicMock()
        mock_acl.is_allowed.return_value = True
        mock_acl.requires_review.return_value = False
        mock_acl.requires_permission.return_value = False

        mock_persona = MagicMock()
        mock_persona.tool_acl = mock_acl

        mock_engine = MagicMock()
        mock_engine.active_persona = mock_persona

        gate = PermissionGate(persona_engine=mock_engine)
        result = gate.check("nmap -sV", tool="nmap")
        assert result.allowed is True
        assert result.stage == "approved"

    @pytest.mark.skip(reason="persona engine deferred to v2.0")
    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_persona_acl_blocks_tool(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])

        mock_acl = MagicMock()
        mock_acl.is_allowed.return_value = False

        mock_persona = MagicMock()
        mock_persona.tool_acl = mock_acl

        mock_engine = MagicMock()
        mock_engine.active_persona = mock_persona

        gate = PermissionGate(persona_engine=mock_engine)
        result = gate.check("nmap -sV", tool="nmap")
        assert result.allowed is False
        assert result.stage == "permission"
        assert "not in allowed list" in result.reason

    @pytest.mark.skip(reason="persona engine deferred to v2.0")
    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_persona_acl_requires_review(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])

        mock_acl = MagicMock()
        mock_acl.is_allowed.return_value = True
        mock_acl.requires_review.return_value = True

        mock_persona = MagicMock()
        mock_persona.tool_acl = mock_acl

        mock_engine = MagicMock()
        mock_engine.active_persona = mock_persona

        gate = PermissionGate(persona_engine=mock_engine)
        result = gate.check("nmap -sV", tool="nmap")
        assert result.allowed is True
        assert result.stage == "review"
        assert result.requires_review is True

    @pytest.mark.skip(reason="persona engine deferred to v2.0")
    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_persona_acl_requires_permission(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])

        mock_acl = MagicMock()
        mock_acl.is_allowed.return_value = True
        mock_acl.requires_review.return_value = False
        mock_acl.requires_permission.return_value = True

        mock_persona = MagicMock()
        mock_persona.tool_acl = mock_acl

        mock_engine = MagicMock()
        mock_engine.active_persona = mock_persona

        gate = PermissionGate(persona_engine=mock_engine)
        result = gate.check("nmap -sV", tool="nmap")
        assert result.allowed is True
        assert result.stage == "permission"
        assert result.requires_review is True

    @pytest.mark.skip(reason="persona engine deferred to v2.0")
    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_persona_engine_missing_acl(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])

        mock_engine = MagicMock()
        mock_engine.active_persona = None

        gate = PermissionGate(persona_engine=mock_engine)
        result = gate.check("ls", tool="shell")
        assert result.allowed is True
        assert result.stage == "approved"
