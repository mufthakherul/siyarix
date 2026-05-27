"""Session kernel and operation cards for mode-oriented UX flows."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4


class SessionPersistenceLevel(StrEnum):
    """Session persistence boundary."""

    EPHEMERAL = "ephemeral"
    WORKSPACE = "workspace"
    ORG_SHARED = "org_shared"


@dataclass
class OperationCard:
    """Operation tracking card for UX timeline/state."""

    operation_id: str
    instruction: str
    state: str = "planned"
    mode: str = "integrated"
    risk_tier: str = "low"
    retries: int = 0
    artifacts: list[str] = field(default_factory=list)
    audit_hash: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


@dataclass
class SessionContext:
    """Canonical session context for routing, policy, and UX rendering."""

    session_id: str
    identity: str = "local-user"
    objective: str = ""
    scope: str = ""
    policy_context: dict[str, Any] = field(default_factory=dict)
    model_context: dict[str, Any] = field(default_factory=dict)
    tool_context: dict[str, Any] = field(default_factory=dict)
    persistence: SessionPersistenceLevel = SessionPersistenceLevel.WORKSPACE
    operations: list[OperationCard] = field(default_factory=list)


class SessionKernel:
    """Manage session state and operation cards."""

    def __init__(self, base_dir: Path | None = None) -> None:
        root = base_dir or Path.home() / ".siyarix" / "kernel_sessions"
        root.mkdir(parents=True, exist_ok=True)
        self._root = root

    def start(
        self,
        objective: str = "",
        scope: str = "",
        identity: str = "local-user",
        persistence: SessionPersistenceLevel = SessionPersistenceLevel.WORKSPACE,
    ) -> SessionContext:
        return SessionContext(
            session_id=str(uuid4())[:12],
            identity=identity,
            objective=objective,
            scope=scope,
            persistence=persistence,
        )

    def add_operation(
        self, session: SessionContext, instruction: str, mode: str, risk_tier: str
    ) -> OperationCard:
        op = OperationCard(
            operation_id=str(uuid4())[:12],
            instruction=instruction,
            mode=mode,
            risk_tier=risk_tier,
        )
        session.operations.append(op)
        return op

    def update_operation(
        self,
        session: SessionContext,
        operation_id: str,
        *,
        state: str | None = None,
        retries: int | None = None,
        artifact: str | None = None,
        audit_hash: str | None = None,
    ) -> OperationCard | None:
        target = next(
            (o for o in session.operations if o.operation_id == operation_id), None
        )
        if not target:
            return None
        if state is not None:
            target.state = state
        if retries is not None:
            target.retries = retries
        if artifact:
            target.artifacts.append(artifact)
        if audit_hash is not None:
            target.audit_hash = audit_hash
        target.updated_at = datetime.now(tz=UTC).isoformat()
        return target

    def save(self, session: SessionContext) -> Path:
        path = self._root / f"{session.session_id}.json"
        data = asdict(session)
        data["persistence"] = session.persistence.value
        path.write_text(json.dumps(data, indent=2))
        return path

    def load(self, session_id: str) -> SessionContext | None:
        path = self._root / f"{session_id}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        operations = [OperationCard(**row) for row in data.get("operations", [])]
        return SessionContext(
            session_id=data["session_id"],
            identity=data.get("identity", "local-user"),
            objective=data.get("objective", ""),
            scope=data.get("scope", ""),
            policy_context=data.get("policy_context", {}) or {},
            model_context=data.get("model_context", {}) or {},
            tool_context=data.get("tool_context", {}) or {},
            persistence=SessionPersistenceLevel(data.get("persistence", "workspace")),
            operations=operations,
        )
