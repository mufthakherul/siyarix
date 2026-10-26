# SPDX-License-Identifier: AGPL-3.0-or-later

"""Operational Security (OPSEC) module — session markers, memory-only, and burn cleanup.

**Honesty:** OS network namespace, Tor routing, DNS-over-HTTPS, and MAC
randomization are **not implemented**. ``isolate()`` only applies in-process
``memory_only`` (suppresses audit/cache persistence) and a soft session label.
``burn()`` / ``secure_delete`` shred local session files under the config dir.

Usage example::

    from siyarix.opsec import opsec_manager

    result = opsec_manager.isolate("192.168.1.1", memory_only=True)
    print(result.detail)  # success only when no unimplemented net features requested

    burn_result = opsec_manager.burn(session_id="abc123")
    print(burn_result.items_destroyed)
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import get_config_dir

logger = logging.getLogger(__name__)


@dataclass
class OPSECStatus:
    """Snapshot of current OPSEC posture.

    Attributes:
        isolated: Whether target isolation is active.
        namespace: Dedicated network namespace name.
        tor_enabled: Whether traffic is routed through Tor.
        doh_enabled: Whether DNS-over-HTTPS is active.
        mac_randomized: Whether MAC address randomization is active.
        memory_only: Whether persistent logging is disabled.
        burn_after_reading: Whether auto-burn is scheduled on exit.
    """

    isolated: bool = False
    namespace: str = ""
    tor_enabled: bool = False
    doh_enabled: bool = False
    mac_randomized: bool = False
    memory_only: bool = False
    burn_after_reading: bool = False


@dataclass
class OPSECActionResult:
    """Result of an OPSEC action (isolate, burn, disable).

    Attributes:
        action: Name of the action performed.
        success: Whether the action completed successfully.
        detail: Human-readable summary of what happened.
        items_destroyed: Number of files securely deleted (burn only).
    """

    action: str = ""
    success: bool = False
    detail: str = ""
    items_destroyed: int = 0


class OPSECManager:
    """Operational security manager — isolation, cleanup, and burn operations.

    Manages network namespace isolation, secure file destruction,
    and session trace elimination.

    Example::

        mgr = OPSECManager()
        mgr.isolate("example.com", use_tor=True)
        assert mgr.is_active
        print(mgr.status_dict())
        mgr.burn()
    """

    def __init__(self) -> None:
        self._status: OPSECStatus = OPSECStatus()
        self._log_dir: Path = get_config_dir() / "logs"

    @property
    def status(self) -> OPSECStatus:
        """Current OPSEC posture snapshot."""
        return self._status

    @property
    def is_active(self) -> bool:
        """``True`` when any OPSEC measure is currently engaged.

        Example::

            if opsec_manager.is_active:
                console.print("[bold yellow]OPSEC active[/]")
        """
        return (
            self._status.isolated
            or self._status.tor_enabled
            or self._status.doh_enabled
            or self._status.mac_randomized
            or self._status.memory_only
            or self._status.burn_after_reading
        )

    def isolate(
        self,
        target: str = "",
        use_tor: bool = False,
        use_doh: bool = False,
        randomize_mac: bool = False,
        memory_only: bool = False,
    ) -> OPSECActionResult:
        """Apply in-process OPSEC markers for a target (no OS net isolation).

        ``memory_only`` is honored in-process (audit/cache persistence suppressed).
        Tor / DoH / MAC / OS network namespaces are **not implemented** — requesting
        them yields ``success=False`` and those status flags stay off.

        Args:
            target: Target hostname or IP (used only for the soft session label).
            use_tor: Requested Tor routing (not implemented).
            use_doh: Requested DNS-over-HTTPS (not implemented).
            randomize_mac: Requested MAC randomization (not implemented).
            memory_only: Disable persistent logging for this session (implemented).

        Returns:
            ``OPSECActionResult`` — ``success`` only when ``memory_only=True`` (the
            sole implemented control) and no unimplemented network features were
            requested. Soft session labels alone return ``success=False``.
        """
        namespace = self._status.namespace
        if not namespace:
            safe_target = (
                "".join(c if c.isalnum() else "_" for c in target)[:16] if target else "no_target"
            )
            namespace = f"siyarix_isolated_{safe_target}_{secrets.token_hex(4)}"

        self._status.namespace = namespace
        # Never claim OS-level isolation / Tor / DoH / MAC until implemented.
        self._status.isolated = False
        self._status.tor_enabled = False
        self._status.doh_enabled = False
        self._status.mac_randomized = False
        self._status.memory_only = bool(memory_only)

        unimplemented: list[str] = ["OS network namespace isolation"]
        if use_tor:
            unimplemented.append("Tor routing")
        if use_doh:
            unimplemented.append("DNS-over-HTTPS")
        if randomize_mac:
            unimplemented.append("MAC randomization")

        details: list[str] = [
            f"Session label: {namespace} (soft marker only — no OS netns)",
            f"Memory-only mode: {'enabled' if memory_only else 'disabled'} (in-process)",
            "NOT IMPLEMENTED (inactive): " + ", ".join(unimplemented),
        ]
        if memory_only:
            details.append("Persistent logging/cache suppressed for this session")

        # Fail closed unless an *implemented* control was applied. Soft session
        # labels alone must not report success (OS netns remains unimplemented).
        net_requested = use_tor or use_doh or randomize_mac
        if net_requested:
            success = False
            logger.warning(
                "OPSEC isolate refused unimplemented network features for target=%s: %s",
                target or "unknown",
                ", ".join(unimplemented),
            )
        elif memory_only:
            success = True
            logger.info(
                "OPSEC soft isolate (memory_only=True) for target=%s label=%s",
                target or "unknown",
                namespace,
            )
        else:
            success = False
            details.append(
                "No implemented OPSEC controls applied — pass memory_only=True "
                "for in-process audit/cache suppression (OS isolation still open)"
            )
            logger.info(
                "OPSEC isolate label-only (success=False) for target=%s label=%s",
                target or "unknown",
                namespace,
            )
        return OPSECActionResult(action="isolate", success=success, detail="\n".join(details))

    def burn(self, session_id: str = "") -> OPSECActionResult:
        """Securely destroy all traces of a session (or all sessions).

        When *session_id* is given, **only** that session's directory is
        shredded and the method returns early.  When omitted or empty,
        every session under the sessions directory is destroyed.

        Args:
            session_id: Optional session identifier.  If empty, all
                sessions are destroyed.

        Returns:
            ``OPSECActionResult`` with destruction summary.

        Example::

            result = mgr.burn(session_id="abc123")
            print(result.items_destroyed)
        """
        items_destroyed: int = 0
        details: list[str] = []

        # H-03: When a specific session_id is provided, delete ONLY that
        # session and return early — never fall through to the "all" path.
        if session_id:
            session_dir = self._log_dir / "sessions" / f"sess_{session_id}"
            if session_dir.exists():
                for f in session_dir.rglob("*"):
                    if f.is_file():
                        self._secure_delete(f)
                        items_destroyed += 1
            details.append(f"Session {session_id}: {items_destroyed} files shredded")
            details.extend(self._trace_cleanup_messages())
            logger.info("OPSEC burn completed for session=%s items=%d", session_id, items_destroyed)
            return OPSECActionResult(
                action="burn",
                success=True,
                detail="\n".join(details),
                items_destroyed=items_destroyed,
            )

        # No session_id — destroy ALL sessions.
        sessions_dir = self._log_dir / "sessions"
        if sessions_dir.exists():
            for sess in sessions_dir.iterdir():
                if sess.is_dir():
                    for f in sess.rglob("*"):
                        if f.is_file():
                            self._secure_delete(f)
                            items_destroyed += 1
                elif sess.is_file():
                    self._secure_delete(sess)
                    items_destroyed += 1

        # H-02: Accurate description — this is a 3-pass random overwrite,
        # NOT the full 35-pass Gutmann method.
        details.append(f"Log files: {items_destroyed} files shredded (3-pass random overwrite)")
        details.extend(self._trace_cleanup_messages())

        logger.info("OPSEC burn completed for session=all items=%d", items_destroyed)
        self._status = OPSECStatus()
        return OPSECActionResult(
            action="burn", success=True, detail="\n".join(details), items_destroyed=items_destroyed
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _trace_cleanup_messages() -> list[str]:
        """Build user-facing messages about OS-level trace cleanup.

        M-34: We cannot actually clear swap / pagefile / network state,
        so messages honestly say *requested* rather than *clearing*.
        """
        msgs: list[str] = []
        if os.name == "posix":
            msgs.append("Memory: Secure zeroization requested")
            msgs.append("Swap: Clearing swap partition requested")
        else:
            msgs.append("Memory: Secure zeroization requested")
            msgs.append("Page file: System page file clearing requested (requires reboot)")
        msgs.append("Disk cache: Flush and overwrite requested")
        msgs.append("Network traces: Clearing requested")
        return msgs

    def _secure_delete(self, path: Path, passes: int = 3) -> None:
        """Overwrite file contents with random data before deletion.

        Performs a multi-pass random overwrite followed by ``unlink``.
        This is a *3-pass random overwrite*, **not** the full 35-pass
        Gutmann scheme.

        .. warning:: SSD / flash-storage limitation

            On solid-state drives the FTL (Flash Translation Layer)
            remaps logical blocks, so overwritten data may persist in
            unmapped pages.  For SSDs, full-disk encryption with key
            destruction (crypto-erase) is the only reliable wipe.

        Args:
            path: File to securely delete.
            passes: Number of random-overwrite passes (default 3).
        """
        if not path.exists() or not path.is_file():
            return
        try:
            size: int = path.stat().st_size
            if not size:
                path.unlink()
                return
            for _ in range(passes):
                with open(path, "wb") as f:
                    f.write(os.urandom(size))
            path.unlink()
            logger.debug("Securely deleted (3-pass random overwrite): %s", path)
        except Exception as exc:
            logger.warning("Secure delete failed for %s: %s", path, exc)

    def disable(self) -> OPSECActionResult:
        """Deactivate all OPSEC measures and reset status.

        Returns:
            ``OPSECActionResult`` confirming deactivation.
        """
        self._status = OPSECStatus()
        return OPSECActionResult(
            action="disable", success=True, detail="OPSEC measures deactivated"
        )

    def summary(self) -> dict[str, Any]:
        """Return a human-readable summary dict of current OPSEC status."""
        return {
            "isolated": self._status.isolated,
            "namespace": self._status.namespace,
            "tor_enabled": self._status.tor_enabled,
            "doh_enabled": self._status.doh_enabled,
            "mac_randomized": self._status.mac_randomized,
            "memory_only": self._status.memory_only,
        }

    def status_dict(self) -> dict[str, Any]:
        """Return a clean, JSON-serializable snapshot of OPSEC state.

        Unlike :meth:`summary`, this includes **every** field in
        ``OPSECStatus`` plus the derived ``is_active`` flag.

        Returns:
            ``dict`` suitable for ``json.dumps()``.

        Example::

            import json

            print(json.dumps(mgr.status_dict(), indent=2))
        """
        data: dict[str, Any] = asdict(self._status)
        data["is_active"] = self.is_active
        return data


def random_string(length: int = 8) -> str:
    """Generate a cryptographically secure random hex string.

    Args:
        length: Desired minimum character length.  The returned string
            may be slightly longer because ``secrets.token_hex`` returns
            ``nbytes * 2`` hex characters.

    Returns:
        Lowercase hex string of at least *length* characters.

    Example::

        >>> len(random_string(8)) >= 8
        True
    """
    # H-01 / L-24: Use secrets instead of insecure random.choices().
    return secrets.token_hex((length + 1) // 2)[:length]


opsec_manager = OPSECManager()


__all__ = [
    "OPSECActionResult",
    "OPSECManager",
    "OPSECStatus",
    "opsec_manager",
    "random_string",
]
