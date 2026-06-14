# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.permission_gate — permission gate integration."""

from __future__ import annotations


from siyarix.permission_gate import GateResult, PermissionGate


class TestCheckPermissionGate:
    def test_approved_returns_value(self) -> None:
        gate = PermissionGate()
        result = gate.check("ls -la", "shell")
        assert isinstance(result, GateResult)
        assert result.allowed is True
        assert result.stage == "approved"

    def test_forbidden_returns_marker(self) -> None:
        gate = PermissionGate()
        result = gate.check("rm -rf /", "shell")
        assert isinstance(result, GateResult)
        assert result.allowed is False
        assert result.stage == "forbidden"

    def test_review_interactive_confirm(self) -> None:
        gate = PermissionGate()
        result = gate.check("nmap -sV 192.168.1.1", "nmap")
        assert isinstance(result, GateResult)

    def test_review_interactive_cancel(self) -> None:
        gate = PermissionGate()
        result = gate.check("nmap -sV 192.168.1.1", "nmap")
        assert isinstance(result, GateResult)

    def test_review_non_interactive_returns_original(self) -> None:
        gate = PermissionGate()
        result = gate.check("echo hello", "shell")
        assert isinstance(result, GateResult)
        assert result.allowed is True

    def test_gate_exception_returns_forbidden(self) -> None:
        gate = PermissionGate()
        result = gate.check("", "shell")
        assert isinstance(result, GateResult)
        assert result.allowed is False
        assert result.stage == "syntax"
