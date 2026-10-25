# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared hard-blocks for destructive shell payloads.

Used by the executor, ToolRegistry, PermissionGate patterns, and subprocess
last-line validation so registry/playbook/deep-scan paths cannot bypass
``BaseExecutor.check_destructive``.
"""

from __future__ import annotations

import re

from siyarix.exceptions import PermissionDeniedError

_FORK_BOMB_MARKERS = (":(){", "::&")
_ALLOWED_DD_OF = frozenset({"/dev/null", "/dev/zero"})
_RM_DESTRUCTIVE_RE = re.compile(
    r"\brm\b[\s]+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s*)+|\brm\b\s+--(?:recursive|force)",
    re.IGNORECASE,
)
_SYSTEM_RM_PATHS = (" /", " /*", " /etc", " /var", " /bin", " /sbin", " /usr", " /home")
_PARTITION_RE = re.compile(r"\b(mkfs(?:\.\w+)?|fdisk|parted|mkswap)\b", re.IGNORECASE)
_DD_OF_RE = re.compile(r"\bof=(\S+)", re.IGNORECASE)
_DD_WORD_RE = re.compile(r"\bdd\b", re.IGNORECASE)


def assert_command_not_destructive(command: str) -> None:
    """Raise :class:`PermissionDeniedError` for fork bombs, disk wipes, and mkfs/fdisk."""
    cmd_clean = (command or "").strip().lower()
    if not cmd_clean:
        return

    if any(marker in cmd_clean for marker in _FORK_BOMB_MARKERS):
        raise PermissionDeniedError(
            "Destructive command detected: Fork bomb execution is blocked."
        )

    if _DD_WORD_RE.search(cmd_clean):
        of_matches = _DD_OF_RE.findall(cmd_clean)
        if of_matches:
            of_target = of_matches[-1]  # last ``of=`` wins
            if of_target.startswith("/dev/") and of_target not in _ALLOWED_DD_OF:
                raise PermissionDeniedError(
                    "Destructive command detected: Overwriting block devices is blocked."
                )

    if _RM_DESTRUCTIVE_RE.search(cmd_clean) and any(
        path in cmd_clean for path in _SYSTEM_RM_PATHS
    ):
        raise PermissionDeniedError(
            "Destructive command detected: Deleting system directory is blocked."
        )

    if _PARTITION_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Formatting storage devices is blocked."
        )


__all__ = ["assert_command_not_destructive"]
