# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.engine.safety — permission gate integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from siyarix.engine.safety import FORBIDDEN_MARKER, check_permission_gate


class TestCheckPermissionGate:
    @patch("siyarix.permission_gate.PermissionGate")
    async def test_approved_returns_value(self, MockGate: MagicMock) -> None:
        gate_instance = MockGate.return_value
        gate_instance.check.return_value = MagicMock(
            stage="approved", requires_review=False
        )
        result = await check_permission_gate("ls -la", "shell", False)
        assert result == "ls -la"

    @patch("siyarix.permission_gate.PermissionGate")
    async def test_forbidden_returns_marker(self, MockGate: MagicMock) -> None:
        gate_instance = MockGate.return_value
        gate_instance.check.return_value = MagicMock(
            stage="forbidden", requires_review=False
        )
        result = await check_permission_gate("rm -rf /", "shell", False)
        assert result == FORBIDDEN_MARKER

    @patch("siyarix.permission_gate.PermissionGate")
    @patch("siyarix.shell_review.review_and_confirm")
    async def test_review_interactive_confirm(
        self, mock_review: MagicMock, MockGate: MagicMock
    ) -> None:
        gate_instance = MockGate.return_value
        gate_instance.check.return_value = MagicMock(
            stage="review", requires_review=True, reason="potentially dangerous"
        )
        mock_review.return_value = "ls -la"
        result = await check_permission_gate("ls -la", "shell", True)
        assert result == "ls -la"

    @patch("siyarix.permission_gate.PermissionGate")
    @patch("siyarix.shell_review.review_and_confirm")
    async def test_review_interactive_cancel(
        self, mock_review: MagicMock, MockGate: MagicMock
    ) -> None:
        gate_instance = MockGate.return_value
        gate_instance.check.return_value = MagicMock(
            stage="review", requires_review=True, reason="potentially dangerous"
        )
        mock_review.return_value = None
        result = await check_permission_gate("ls -la", "shell", True)
        assert result == FORBIDDEN_MARKER

    @patch("siyarix.permission_gate.PermissionGate")
    async def test_review_non_interactive_returns_original(
        self, MockGate: MagicMock
    ) -> None:
        gate_instance = MockGate.return_value
        gate_instance.check.return_value = MagicMock(
            stage="review", requires_review=True, reason="potentially dangerous"
        )
        result = await check_permission_gate("ls -la", "shell", False)
        assert result == "ls -la"

    @patch("siyarix.permission_gate.PermissionGate")
    async def test_gate_exception_returns_forbidden(self, MockGate: MagicMock) -> None:
        gate_instance = MockGate.return_value
        gate_instance.check.side_effect = RuntimeError("gate failed")
        result = await check_permission_gate("anything", "shell", False)
        assert result == FORBIDDEN_MARKER
