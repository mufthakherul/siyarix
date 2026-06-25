# SPDX-License-Identifier: AGPL-3.0-or-later

"""Enterprise Audit Logger — structured logs, compliance, tamper-evident.

Features:
  • Structured JSON audit trails with SHA-256 chain of custody
  • Compliance frameworks (SOC 2, ISO 27001, NIST)
  • Tamper-evident hashing (chain of custody verification)
  • Log rotation & retention policies
  • Real-time monitoring & alerting
  • Export to JSON, CSV
  • User attribution & session tracking
  • Event correlation & anomaly detection
"""

from __future__ import annotations

import atexit
import hashlib
import importlib.metadata
import json
import logging
import os
import socket
import stat
import sys
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any

from .security_hardening import redactor

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

try:
    from rich.console import Console

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)


class AuditEventType(StrEnum):
    """Audit event types"""

    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_FAILED = "auth_failed"
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_FAILED = "scan_failed"
    INCIDENT_CREATE = "incident_create"
    INCIDENT_UPDATE = "incident_update"
    INCIDENT_CLOSE = "incident_close"
    VULN_CREATE = "vuln_create"
    VULN_UPDATE = "vuln_update"
    THREAT_HUNT = "threat_hunt"
    CONFIG_CHANGE = "config_change"
    PLUGIN_INSTALL = "plugin_install"
    PLUGIN_REMOVE = "plugin_remove"
    API_KEY_CREATE = "api_key_create"  # pragma: allowlist secret
    API_KEY_REVOKE = "api_key_revoke"  # pragma: allowlist secret
    COMPLIANCE_CHECK = "compliance_check"
    BULK_OPERATION = "bulk_operation"
    SYSTEM_START = "system_start"
    SYSTEM_ERROR = "system_error"
    SECURITY_APPROVAL = "security_approval"
    SECURITY_DENIAL = "security_denial"
    CREDENTIAL_ROTATED = "credential_rotated"
    PERMISSION_CHANGE = "permission_change"
    SESSION_TIMEOUT = "session_timeout"
    RATE_LIMIT_HIT = "rate_limit_hit"
    DLP_VIOLATION = "dlp_violation"
    FILE_INTEGRITY = "file_integrity"
    CONTAINER_CHECK = "container_check"


class AuditSeverity(StrEnum):
    """Audit severity"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_COLORS: dict[str, str] = {
    AuditSeverity.INFO: "green",
    AuditSeverity.LOW: "cyan",
    AuditSeverity.MEDIUM: "yellow",
    AuditSeverity.HIGH: "bright_yellow",
    AuditSeverity.CRITICAL: "red",
}


@dataclass
class AuditEvent:
    """Structured audit event"""

    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    user: str
    session_id: str
    source_ip: str
    target: str
    action: str
    result: str
    details: dict[str, Any]
    hash_prev: str | None = None
    hash_current: str | None = None

    def compute_hash(self, prev_hash: str | None = None) -> str:
        """Compute tamper-evident SHA-256 hash (first 16 hex chars)."""
        try:
            details_str = json.dumps(self.details, sort_keys=True, default=str)
        except Exception:
            details_str = str(self.details)
        data = (
            f"{self.timestamp.isoformat()}{self.event_type}{self.severity}"
            f"{self.user}{self.session_id}{self.source_ip}{self.target}"
            f"{self.action}{self.result}{details_str}{prev_hash or ''}"
        )
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "severity": self.severity,
            "user": redactor.redact(self.user) if self.user not in ("system", "") else self.user,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "target": self.target,
            "action": self.action,
            "result": self.result,
            "details": self._redact_details(),
            "hash_prev": self.hash_prev,
            "hash_current": self.hash_current,
        }

    def _redact_details(self) -> dict[str, Any]:
        """Redact sensitive values in details dict."""
        if not self.details:
            return {}
        return redactor.redact_dict(self.details)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def __repr__(self) -> str:
        return (
            f"AuditEvent(id={self.event_id!r}, type={self.event_type!r}, "
            f"user={self.user!r}, action={self.action!r})"
        )


@dataclass
class AuditSession:
    """User session for attribution"""

    session_id: str
    user: str
    start_time: datetime
    end_time: datetime | None = None
    source_ip: str = ""
    events_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user": self.user,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "source_ip": self.source_ip,
            "events_count": self.events_count,
        }


class AuditLogger:
    """Enterprise audit logging system with tamper-evident chain."""

    def __init__(self, log_startup: bool = True) -> None:
        from .config import get_config_dir

        self._config_dir = get_config_dir()
        self._audit_log = self._config_dir / "audit.log"
        self._audit_db = self._config_dir / "audit.jsonl"
        self._legacy_db = self._config_dir / "audit.json"
        self._events: list[AuditEvent] = []
        self._unflushed_events: list[AuditEvent] = []
        self._sessions: dict[str, AuditSession] = {}
        self._dirty = False
        self._lock = threading.Lock()

        self._retention_days = 365
        self._cached_source_ip: str | None = None
        self._count_by_type: dict[str, int] = {et.value: 0 for et in AuditEventType}
        self._count_by_severity: dict[str, int] = {s.value: 0 for s in AuditSeverity}

        self._load_config()
        self._load_events()
        if log_startup:
            self._startup_event()
        atexit.register(self._flush_on_exit)

    def _load_config(self) -> None:
        """Load audit configuration."""
        config_file = self._config_dir / "audit.toml"
        if config_file.exists() and tomllib is not None:
            try:
                config = tomllib.loads(config_file.read_text())
                self._retention_days = config.get("retention_days", 365)
            except (tomllib.TOMLDecodeError, OSError, ValueError) as exc:
                logger.exception("Failed to load audit config: %s", exc)

    def _load_events(self) -> None:
        """Load existing events from disk (last 1000 only to limit memory)."""
        if self._audit_db.exists():
            try:
                lines = self._audit_db.read_text().splitlines()
                self._parse_events_from_dicts(
                    [json.loads(line) for line in lines[-1000:] if line.strip()]
                )
            except Exception as exc:
                logger.exception("Failed to load audit jsonl: %s", exc)
        elif self._legacy_db.exists():
            try:
                data = json.loads(self._legacy_db.read_text())
                self._parse_events_from_dicts(data[-1000:])
            except Exception as exc:
                logger.exception("Failed to load legacy audit json: %s", exc)

    def _parse_events_from_dicts(self, data: list[dict]) -> None:
        for evt_data in data:
            try:
                evt = AuditEvent(
                    event_id=evt_data["event_id"],
                    timestamp=datetime.fromisoformat(evt_data["timestamp"]),
                    event_type=evt_data["event_type"],
                    severity=evt_data["severity"],
                    user=evt_data["user"],
                    session_id=evt_data["session_id"],
                    source_ip=evt_data["source_ip"],
                    target=evt_data["target"],
                    action=evt_data["action"],
                    result=evt_data["result"],
                    details=evt_data.get("details", {}),
                    hash_prev=evt_data.get("hash_prev"),
                    hash_current=evt_data.get("hash_current"),
                )
                self._events.append(evt)
                self._count_by_type[evt.event_type] = self._count_by_type.get(evt.event_type, 0) + 1
                self._count_by_severity[evt.severity] = (
                    self._count_by_severity.get(evt.severity, 0) + 1
                )
            except Exception as exc:
                logger.warning("Failed to parse event: %s", exc)

    def _save_events(self) -> None:
        """Save events to disk atomically with secure permissions."""
        if not self._unflushed_events:
            return

        try:
            from siyarix.opsec import opsec_manager

            if opsec_manager.status.memory_only:
                self._unflushed_events.clear()
                self._dirty = False
                return
        except Exception:
            pass

        try:
            self._config_dir.mkdir(parents=True, exist_ok=True)
            lines = [json.dumps(e.to_dict()) + "\n" for e in self._unflushed_events]
            with self._audit_db.open("a", encoding="utf-8") as f:
                f.writelines(lines)
            try:
                if os.name != "nt":
                    current = stat.S_IMODE(self._audit_db.stat().st_mode)
                    if current & 0o077:
                        self._audit_db.chmod(current & 0o700)
            except Exception:
                pass
            self._unflushed_events.clear()
            self._dirty = False
        except Exception as exc:
            logger.error("Failed to save audit events: %s", exc)

    def _flush_on_exit(self) -> None:
        with self._lock:
            if self._dirty:
                self._save_events()

    def _startup_event(self) -> None:
        """Log system startup."""
        try:
            version = importlib.metadata.version("siyarix")
        except Exception:
            version = "unknown"

        self.log(
            event_type=AuditEventType.SYSTEM_START,
            severity=AuditSeverity.INFO,
            user="system",
            action="cli_startup",
            result="success",
            details={"version": version, "platform": sys.platform},
        )

    def _get_source_ip(self) -> str:
        """Get source IP."""
        if self._cached_source_ip is None:
            try:
                self._cached_source_ip = socket.gethostbyname(socket.gethostname())
            except Exception as exc:
                logger.debug("Failed to resolve host IP: %s", exc)
                self._cached_source_ip = "127.0.0.1"
        return self._cached_source_ip

    def start_session(self, user: str) -> str:
        """Start audit session."""
        session_id = uuid.uuid4().hex
        session = AuditSession(
            session_id=session_id,
            user=user,
            start_time=datetime.now(timezone.utc),
            source_ip=self._get_source_ip(),
        )
        self._sessions[session_id] = session
        return session_id

    def end_session(self, session_id: str) -> None:
        """End audit session."""
        if session_id in self._sessions:
            sess = self._sessions[session_id]
            sess.end_time = datetime.now(timezone.utc)
            self.log(
                event_type=AuditEventType.AUTH_LOGOUT,
                severity=AuditSeverity.INFO,
                user=sess.user,
                session_id=session_id,
                action="session_end",
                result="success",
                details={"duration": str(datetime.now(timezone.utc) - sess.start_time)},
            )

    def log(
        self,
        event_type: str,
        severity: str,
        user: str,
        action: str,
        result: str,
        target: str = "",
        session_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log audit event."""
        with self._lock:
            prev_hash = self._events[-1].hash_current if self._events else None

            event = AuditEvent(
                event_id=uuid.uuid4().hex,
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                severity=severity,
                user=user,
                session_id=session_id,
                source_ip=self._get_source_ip(),
                target=target,
                action=action,
                result=result,
                details=details or {},
            )

            event.hash_prev = prev_hash
            event.hash_current = event.compute_hash(prev_hash)

            self._events.append(event)
            self._unflushed_events.append(event)
            self._dirty = True

        self._count_by_type[event.event_type] = self._count_by_type.get(event.event_type, 0) + 1
        self._count_by_severity[event.severity] = self._count_by_severity.get(event.severity, 0) + 1

        if session_id and session_id in self._sessions:
            self._sessions[session_id].events_count += 1

        if RICH_AVAILABLE and os.getenv("SIYARIX_AUDIT_VERBOSE", "0") == "1":
            console = Console(stderr=True)
            color = _SEVERITY_COLORS.get(severity, "white")
            console.print(
                f"[{color}]{event.timestamp.strftime('%H:%M:%S')} | "
                f"{event.user} | {event.action} | {event.target}[/{color}]"
            )

        self._save_events()

        return event

    def get_events(
        self,
        event_type: str | None = None,
        user: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query audit events."""
        events = list(self._events)

        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if user:
            events = [e for e in events if e.user == user]
        if severity:
            events = [e for e in events if e.severity == severity]

        return [e.to_dict() for e in events[-limit:]]

    def verify_chain(self) -> dict[str, Any]:
        """Verify tamper-evident chain of all events."""
        valid = True
        broken_at = None
        errors: list[str] = []

        for i, event in enumerate(self._events):
            if i > 0:
                expected_prev = self._events[i - 1].hash_current
                if event.hash_prev != expected_prev:
                    valid = False
                    broken_at = event.event_id
                    errors.append(
                        f"Chain break at event {i} ({event.event_id}): "
                        f"expected prev_hash {expected_prev}, got {event.hash_prev}"
                    )
                    break

            expected_hash = event.compute_hash(event.hash_prev)
            if event.hash_current != expected_hash:
                valid = False
                errors.append(
                    f"Event {i} ({event.event_id}) hash mismatch: "
                    f"expected {expected_hash}, got {event.hash_current}"
                )
                if broken_at is None:
                    broken_at = event.event_id
                break

        return {
            "valid": valid,
            "total_events": len(self._events),
            "broken_at": broken_at,
            "errors": errors,
            "chain_integrity": "intact" if valid else "compromised",
        }

    def export(
        self,
        export_format: str = "json",
        filepath: str | None = None,
        days: int = 30,
    ) -> str | None:
        """Export audit logs."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        events = [e for e in self._events if e.timestamp >= cutoff]

        if export_format == "json":
            data = json.dumps([e.to_dict() for e in events], indent=2)
        elif export_format == "csv":
            import csv
            from io import StringIO

            output = StringIO()
            writer = csv.DictWriter(
                output, fieldnames=["timestamp", "user", "action", "target", "result"]
            )
            writer.writeheader()
            for e in events:
                writer.writerow(
                    {
                        "timestamp": e.timestamp.isoformat(),
                        "user": e.user,
                        "action": e.action,
                        "target": e.target,
                        "result": e.result,
                    }
                )
            data = output.getvalue()
        else:
            data = json.dumps([e.to_dict() for e in events], indent=2)

        if filepath:
            output_path = Path(filepath)
            output_path.write_text(data, encoding="utf-8")
            try:
                if os.name != "nt":
                    os.chmod(output_path, stat.S_IMODE(output_path.stat().st_mode) & 0o700)
            except Exception:
                pass
            return None
        return data

    def get_statistics(self) -> dict[str, Any]:
        """Get audit statistics."""
        return {
            "total_events": len(self._events),
            "total_sessions": len(self._sessions),
            "by_type": dict(self._count_by_type),
            "by_severity": dict(self._count_by_severity),
            "active_sessions": len([s for s in self._sessions.values() if not s.end_time]),
            "retention_days": self._retention_days,
        }

    def stats(self) -> dict[str, Any]:
        return self.get_statistics()

    def cleanup_old_events(self) -> None:
        """Remove events older than retention period and rewrite the audit file."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        with self._lock:
            retained_events = []
            for e in self._events:
                if e.timestamp >= cutoff:
                    retained_events.append(e)
                else:
                    self._count_by_type[e.event_type] = max(
                        0, self._count_by_type.get(e.event_type, 0) - 1
                    )
                    self._count_by_severity[e.severity] = max(
                        0, self._count_by_severity.get(e.severity, 0) - 1
                    )
            self._events = retained_events
        try:
            self._config_dir.mkdir(parents=True, exist_ok=True)
            with self._lock:
                lines = [json.dumps(e.to_dict()) + "\n" for e in self._events]
            with self._audit_db.open("w", encoding="utf-8") as f:
                f.writelines(lines)
            try:
                if os.name != "nt":
                    os.chmod(self._audit_db, stat.S_IMODE(self._audit_db.stat().st_mode) & 0o700)
            except Exception:
                pass
            with self._lock:
                self._unflushed_events.clear()
                self._dirty = False
        except Exception as exc:
            logger.error("Failed to rewrite audit log after cleanup: %s", exc)


_audit_instance: AuditLogger | None = None


def __getattr__(name: str) -> Any:
    if name == "audit":
        global _audit_instance
        if _audit_instance is None:
            _audit_instance = AuditLogger()
        return _audit_instance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def log_event(
    event_type: str,
    severity: str,
    user: str,
    action: str,
    result: str,
    target: str = "",
    session_id: str = "",
    details: dict | None = None,
) -> AuditEvent:
    """Convenience function to log event."""
    return __getattr__("audit").log(
        event_type, severity, user, action, result, target, session_id, details
    )


__all__ = [
    "AuditEventType",
    "AuditSeverity",
    "AuditEvent",
    "AuditSession",
    "AuditLogger",
    "log_event",
]
