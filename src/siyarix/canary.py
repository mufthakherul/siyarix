# SPDX-License-Identifier: AGPL-3.0-or-later

"""Canary token deployment and management.

Creates and manages deception tokens (canary tokens) to detect
unauthorized access as described in Chapter 20.2. Supports
multiple token types including web, DNS, and credential tokens.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


class CanaryTokenType(StrEnum):
    WEB = "web"
    DNS = "dns"
    AWS_KEY = "aws_key"
    CREDENTIAL = "credential"
    FILE = "file"
    DB_RECORD = "db_record"
    API_KEY = "api_key"


@dataclass
class CanaryToken:
    """A deception canary token."""

    token_id: str = ""
    token_type: CanaryTokenType = CanaryTokenType.WEB
    value: str = ""
    location: str = ""
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    triggered: bool = False
    triggered_at: str = ""
    triggered_by: str = ""
    alert_callback: str = ""


@dataclass
class CanaryDeployment:
    """Result of a canary token deployment."""

    tokens: list[CanaryToken] = field(default_factory=list)
    target: str = ""
    deployment_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    deployed_at: str = field(default_factory=lambda: datetime.now().isoformat())


TOKEN_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web": [
        {
            "location": "/admin.bak",
            "description": "Fake backup file honeypot",
            "type": "file",
        },
        {
            "location": "/config.json",
            "description": "Fake config with honeypot keys",
            "type": "aws_key",
        },
        {
            "location": "/debug.php",
            "description": "Fake debug endpoint honeypot",
            "type": "web",
        },
        {
            "location": "/.git/config",
            "description": "Fake git exposure honeypot",
            "type": "file",
        },
    ],
    "dns": [
        {
            "location": "canary-{id}.example.com",
            "description": "DNS canary token for subdomain monitoring",
            "type": "dns",
        },
        {
            "location": "alert-{id}.internal-monitor.local",
            "description": "Internal DNS canary",
            "type": "dns",
        },
    ],
    "credential": [
        {
            "location": "ssh_config",
            "description": "Honeypot SSH credential",
            "type": "credential",
        },
        {
            "location": "ftp_config",
            "description": "Honeypot FTP credential",
            "type": "credential",
        },
    ],
}


class CanaryTokenManager:
    """Manages canary token lifecycle — creation, deployment, tracking, alerts."""

    def __init__(self, storage_dir: Path | None = None) -> None:
        self._storage_dir = storage_dir or Path.home() / ".siyarix" / "canary"
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._tokens: dict[str, CanaryToken] = {}
        self._alert_handlers: list[Callable[[CanaryToken], None]] = []
        self._load_tokens()

    def create_token(
        self,
        token_type: CanaryTokenType,
        location: str = "",
        description: str = "",
        alert_callback: str = "",
    ) -> CanaryToken:
        token_id = uuid.uuid4().hex[:16]
        resolved_location = location or self._default_location(token_type)
        value = self._generate_token_value(token_type, token_id, resolved_location)
        token = CanaryToken(
            token_id=token_id,
            token_type=token_type,
            value=value,
            location=resolved_location,
            description=description or f"{token_type.value} canary token",
            alert_callback=alert_callback,
        )
        self._tokens[token_id] = token
        self._save_tokens()
        logger.info("Canary token created: %s (%s)", token_id, token_type.value)
        return token

    def deploy_to_target(
        self, target: str, token_types: list[CanaryTokenType] | None = None
    ) -> CanaryDeployment:
        types = token_types or [
            CanaryTokenType.WEB,
            CanaryTokenType.DNS,
            CanaryTokenType.CREDENTIAL,
        ]
        deployment = CanaryDeployment(target=target)
        templates = TOKEN_TEMPLATES

        for ttype in types:
            type_key = ttype.value
            type_templates = templates.get(type_key, [])
            for tmpl in type_templates:
                location = tmpl["location"].replace("{id}", uuid.uuid4().hex[:8])
                token = self.create_token(
                    token_type=CanaryTokenType(tmpl["type"]),
                    location=location,
                    description=tmpl["description"],
                )
                deployment.tokens.append(token)

        logger.info("Deployed %d canary tokens to %s", len(deployment.tokens), target)
        return deployment

    def trigger_token(
        self, token_id: str, source: str = "unknown"
    ) -> CanaryToken | None:
        token = self._tokens.get(token_id)
        if not token:
            logger.warning("Trigger for unknown canary token: %s", token_id)
            return None

        token.triggered = True
        token.triggered_at = datetime.now().isoformat()
        token.triggered_by = source
        self._save_tokens()

        logger.warning(
            "CANARY TRIGGERED: %s at %s (by %s)", token_id, token.location, source
        )
        for handler in self._alert_handlers:
            try:
                handler(token)
            except Exception as exc:
                logger.error("Alert handler failed for token %s: %s", token_id, exc)

        return token

    def register_alert_handler(self, handler: Callable[[CanaryToken], None]) -> None:
        self._alert_handlers.append(handler)

    def get_token(self, token_id: str) -> CanaryToken | None:
        return self._tokens.get(token_id)

    def list_tokens(self, include_triggered: bool = False) -> list[CanaryToken]:
        tokens = list(self._tokens.values())
        if not include_triggered:
            tokens = [t for t in tokens if not t.triggered]
        return tokens

    def list_triggered(self) -> list[CanaryToken]:
        return [t for t in self._tokens.values() if t.triggered]

    def delete_token(self, token_id: str) -> bool:
        if token_id in self._tokens:
            del self._tokens[token_id]
            self._save_tokens()
            return True
        return False

    def summary(self) -> dict[str, Any]:
        all_tokens = self._tokens.values()
        return {
            "total_tokens": len(all_tokens),
            "active_tokens": sum(1 for t in all_tokens if not t.triggered),
            "triggered_tokens": sum(1 for t in all_tokens if t.triggered),
            "token_types": {
                ttype.value: sum(1 for t in all_tokens if t.token_type == ttype)
                for ttype in CanaryTokenType
            },
        }

    def _generate_token_value(
        self, token_type: CanaryTokenType, token_id: str, location: str = ""
    ) -> str:
        generators = {
            CanaryTokenType.WEB: lambda: f"<!-- CANARY:{token_id}:{uuid.uuid4().hex[:16]} -->",
            CanaryTokenType.DNS: lambda: (
                f"canary-{token_id}.{location.split('.', 1)[-1] if location else 'siyarix-alert.local'}"
            ),
            CanaryTokenType.AWS_KEY: lambda: f"AKIA{uuid.uuid4().hex[:16].upper()}",
            CanaryTokenType.CREDENTIAL: lambda: f"canary_{token_id}:{uuid.uuid4().hex[:24]}",
            CanaryTokenType.FILE: lambda: f"CANARY_TOKEN_{token_id}_{uuid.uuid4().hex[:16]}",
            CanaryTokenType.DB_RECORD: lambda: f"siyarix_canary_{token_id}",
            CanaryTokenType.API_KEY: lambda: f"phl_{uuid.uuid4().hex[:24]}",
        }
        gen: Callable[[], str] = generators.get(token_type, lambda: token_id)
        return gen()

    def _default_location(self, token_type: CanaryTokenType) -> str:
        defaults = {
            CanaryTokenType.WEB: "/canary.html",
            CanaryTokenType.DNS: f"canary-{uuid.uuid4().hex[:8]}.monitor.local",
            CanaryTokenType.AWS_KEY: "/config/credentials",
            CanaryTokenType.CREDENTIAL: "/etc/honeypot-credentials",
            CanaryTokenType.FILE: os.path.join(tempfile.gettempdir(), f".canary_{uuid.uuid4().hex[:8]}"),
            CanaryTokenType.DB_RECORD: f"canary_records_{uuid.uuid4().hex[:8]}",
            CanaryTokenType.API_KEY: "/.env",
        }
        return defaults.get(token_type, "/canary")

    def _save_tokens(self) -> None:
        path = self._storage_dir / "tokens.json"
        data = {
            tid: {
                "token_id": t.token_id,
                "token_type": t.token_type.value,
                "value": t.value,
                "location": t.location,
                "description": t.description,
                "created_at": t.created_at,
                "triggered": t.triggered,
                "triggered_at": t.triggered_at,
                "triggered_by": t.triggered_by,
                "alert_callback": t.alert_callback,
            }
            for tid, t in self._tokens.items()
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_tokens(self) -> None:
        path = self._storage_dir / "tokens.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for tid, tdata in data.items():
                self._tokens[tid] = CanaryToken(
                    token_id=tdata["token_id"],
                    token_type=CanaryTokenType(tdata["token_type"]),
                    value=tdata.get("value", ""),
                    location=tdata.get("location", ""),
                    description=tdata.get("description", ""),
                    created_at=tdata.get("created_at", ""),
                    triggered=tdata.get("triggered", False),
                    triggered_at=tdata.get("triggered_at", ""),
                    triggered_by=tdata.get("triggered_by", ""),
                    alert_callback=tdata.get("alert_callback", ""),
                )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("Failed to load canary tokens: %s", exc)


__all__ = ["CanaryTokenManager", "CanaryToken", "CanaryDeployment", "CanaryTokenType"]
