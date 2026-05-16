"""Profile and workspace configuration for NexSec Agent."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_PROFILE = "default"

def _config_dir() -> Path:
    override = os.getenv("NEXSEC_CONFIG_DIR")
    return Path(override).expanduser() if override else Path.home() / ".nexsec"

class ProfileStore:
    def __init__(self) -> None:
        self._dir = _config_dir()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._profiles_file = self._dir / "profiles.json"

    def load(self) -> dict:
        if not self._profiles_file.exists():
            return {"active_profile": DEFAULT_PROFILE, "profiles": {}}
        try:
            data = json.loads(self._profiles_file.read_text(encoding="utf-8"))
            if "profiles" not in data:
                data["profiles"] = {}
            if "active_profile" not in data:
                data["active_profile"] = DEFAULT_PROFILE
            return data
        except Exception:
            return {"active_profile": DEFAULT_PROFILE, "profiles": {}}

    def save(self, data: dict) -> None:
        self._profiles_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_active_profile(self) -> str:
        data = self.load()
        active = data.get("active_profile") or DEFAULT_PROFILE
        profiles = data.get("profiles", {})
        if active not in profiles and profiles:
            return max(profiles.keys(), key=lambda key: profiles[key].get("last_used_at", ""))
        return active

    def set_active_profile(self, name: str) -> None:
        data = self.load()
        if name not in data.get("profiles", {}):
            raise ValueError(f"Profile '{name}' not found")
        data["active_profile"] = name
        now = datetime.now(tz=UTC).isoformat()
        data["profiles"][name]["last_used_at"] = now
        self.save(data)

    def list_profiles(self) -> list[dict]:
        data = self.load()
        active = data.get("active_profile", DEFAULT_PROFILE)
        rows = []
        for name, profile in sorted(data.get("profiles", {}).items()):
            rows.append({"name": name, "active": name == active, **profile})
        return rows

    def get_profile(self, name: str | None = None) -> dict | None:
        data = self.load()
        resolved_name = name or self.get_active_profile()
        profile = data.get("profiles", {}).get(resolved_name)
        if profile is None:
            return None
        return {"name": resolved_name, **profile}

    def upsert_profile(
        self,
        name: str,
        *,
        server_url: str,
        org_id: str | None = None,
        auth_method: str = "api_key",
        default_target: str | None = None,
        default_output_format: str = "table",
    ) -> dict:
        data = self.load()
        now = datetime.now(tz=UTC).isoformat()
        existing = data.get("profiles", {}).get(name, {})
        profile = {
            "server_url": server_url,
            "org_id": org_id,
            "auth_method": auth_method,
            "default_target": default_target,
            "default_output_format": default_output_format,
            "created_at": existing.get("created_at", now),
            "last_used_at": now,
        }
        data.setdefault("profiles", {})[name] = profile
        if not data.get("active_profile") or data["active_profile"] not in data["profiles"]:
            data["active_profile"] = name
        self.save(data)
        return {"name": name, **profile}

    def delete_profile(self, name: str) -> bool:
        data = self.load()
        profiles = data.get("profiles", {})
        if name not in profiles:
            return False
        profiles.pop(name)
        if data.get("active_profile") == name:
            if profiles:
                data["active_profile"] = max(
                    profiles.keys(),
                    key=lambda key: profiles[key].get("last_used_at", ""),
                )
            else:
                data["active_profile"] = DEFAULT_PROFILE
        self.save(data)
        return True
