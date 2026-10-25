# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared ToolRegistry construction with production PermissionGate defaults."""

from __future__ import annotations

import os
from typing import Any

from .permission_gate import PermissionGate
from .registry import ToolRegistry

_UNSET: Any = object()


def permission_gate_enabled() -> bool:
    """Return True unless SIYARIX_SAFE_MODE explicitly disables the gate."""
    return os.getenv("SIYARIX_SAFE_MODE", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def make_tool_registry(*, permission_gate: Any = _UNSET) -> ToolRegistry:
    """Build a ToolRegistry; attach PermissionGate by default for production."""
    if permission_gate is _UNSET:
        permission_gate = PermissionGate() if permission_gate_enabled() else None
    return ToolRegistry(permission_gate=permission_gate)
