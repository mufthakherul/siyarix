"""Safety and security checks that happen within the engine flow."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

FORBIDDEN_MARKER = "__forbidden__"


async def check_permission_gate(
    value: str,
    tool_name: str,
    interactive: bool,
) -> str:
    """Check permission gate; return confirmed value, original, or '__forbidden__'."""
    try:
        from ..permission_gate import PermissionGate

        gate = PermissionGate()
        gate_result = gate.check(value, tool=tool_name)
        if gate_result.stage == "forbidden":
            return FORBIDDEN_MARKER
        if gate_result.requires_review and interactive:
            from ..shell_review import review_and_confirm

            confirmed = review_and_confirm(
                value, tool_name, gate_result.reason
            )
            if confirmed is None:
                return FORBIDDEN_MARKER
            return confirmed
    except Exception as exc:
        logger.warning("Permission gate check failed, blocking: %s", exc)
        return FORBIDDEN_MARKER

    return value
