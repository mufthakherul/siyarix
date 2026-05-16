"""Authentication helpers for NexSec Agent CLI."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from .credential_store import CredentialStore
from .profiles import ProfileStore

class AuthManager:
    def __init__(self, credentials: CredentialStore | None = None, profiles: ProfileStore | None = None) -> None:
        self.credentials = credentials or CredentialStore()
        self.profiles = profiles or ProfileStore()

    def login(
        self,
        *,
        profile: str,
        server_url: str,
        api_key: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        org_id: str | None = None,
    ) -> dict:
        if not api_key and not access_token:
            raise ValueError("Either api_key or access_token is required")

        auth_method = "api_key" if api_key else "token"
        self.profiles.upsert_profile(
            profile,
            server_url=server_url,
            org_id=org_id,
            auth_method=auth_method,
        )

        self.credentials.store(profile, server_url, "server_url")
        if org_id:
            self.credentials.store(profile, org_id, "org_id")
        if api_key:
            self.credentials.store(profile, api_key, "api_key")
            self.credentials.delete(profile, "access_token")
        if access_token:
            self.credentials.store(profile, access_token, "access_token")
            self.credentials.delete(profile, "api_key")
        if refresh_token:
            self.credentials.store(profile, refresh_token, "refresh_token")

        self.profiles.set_active_profile(profile)

        health = self._health(server_url, profile)
        return {
            "profile": profile,
            "server_url": server_url,
            "auth_method": auth_method,
            "health": health,
        }

    def logout(self, profile: str) -> None:
        for key in ("api_key", "access_token", "refresh_token", "server_url", "org_id"):
            self.credentials.delete(profile, key)

    def status(self, profile: str) -> dict:
        profile_data = self.profiles.get_profile(profile)
        if not profile_data:
            return {"logged_in": False, "profile": profile, "reason": "profile_not_found"}

        server_url = self.credentials.retrieve(profile, "server_url") or profile_data.get("server_url")
        api_key = self.credentials.retrieve(profile, "api_key")
        access_token = self.credentials.retrieve(profile, "access_token")
        refresh_token = self.credentials.retrieve(profile, "refresh_token")

        logged_in = bool((api_key or access_token) and server_url)
        if not logged_in:
            return {
                "logged_in": False,
                "profile": profile,
                "server_url": server_url,
                "auth_method": profile_data.get("auth_method"),
            }

        me = self._me(server_url, profile)

        return {
            "logged_in": True,
            "profile": profile,
            "server_url": server_url,
            "auth_method": profile_data.get("auth_method"),
            "token_type": "api_key" if api_key else "access_token",
            "has_refresh_token": bool(refresh_token),
            "expires_soon": self._expires_soon(profile),
            "me": me,
        }

    def refresh(self, profile: str) -> dict:
        profile_data = self.profiles.get_profile(profile)
        if not profile_data:
            raise ValueError(f"Profile '{profile}' not found")

        server_url = self.credentials.retrieve(profile, "server_url") or profile_data.get("server_url")
        refresh_token = self.credentials.retrieve(profile, "refresh_token")
        if not server_url:
            raise ValueError("Server URL not configured")
        if not refresh_token:
            raise ValueError("Refresh token not available")

        resp = httpx.post(
            f"{server_url.rstrip('/')}/api/auth/refresh",
            json={"refresh_token": refresh_token},
            timeout=12.0,
        )
        if resp.status_code != 200:
            raise ValueError(f"Token refresh failed ({resp.status_code})")

        payload = resp.json()
        access_token = payload.get("access_token")
        if not access_token:
            raise ValueError("Refresh response missing access_token")
        self.credentials.store(profile, "access_token", access_token)
        new_refresh = payload.get("refresh_token")
        if isinstance(new_refresh, str) and new_refresh:
            self.credentials.store(profile, "refresh_token", new_refresh)
        expires_in = payload.get("expires_in")
        # Default to 55 minutes to refresh before a common 60-minute token expiry window.
        expiry_minutes = 55
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            expiry_minutes = max(1, int(expires_in) // 60)
        self._store_expiry(profile, minutes=expiry_minutes)
        return {"status": "refreshed", "profile": profile}

    def auth_headers(self, profile: str, auto_refresh: bool = True) -> dict[str, str]:
        profile_data = self.profiles.get_profile(profile)
        if not profile_data:
            return {}
        if auto_refresh and self._expires_soon(profile):
            self.refresh(profile)

        token = self.credentials.retrieve(profile, "access_token")
        api_key = self.credentials.retrieve(profile, "api_key")
        if token:
            return {"Authorization": f"Bearer {token}"}
        if api_key:
            return {"X-API-Key": api_key}
        return {}

    def require_auth_headers(self, profile: str, auto_refresh: bool = True) -> dict[str, str]:
        headers = self.auth_headers(profile, auto_refresh=auto_refresh)
        if not headers:
            raise ValueError(f"Profile '{profile}' has no stored credentials. Run 'nexsec auth login'.")
        return headers

    def _health(self, server_url: str, profile: str) -> dict:
        headers = self.auth_headers(profile, auto_refresh=False)
        try:
            resp = httpx.get(f"{server_url.rstrip('/')}/api/health", headers=headers, timeout=8.0)
            return {"ok": resp.status_code < 500, "status_code": resp.status_code}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _me(self, server_url: str, profile: str) -> dict:
        headers = self.auth_headers(profile)
        if not headers:
            return {"available": False}
        try:
            resp = httpx.get(f"{server_url.rstrip('/')}/api/auth/me", headers=headers, timeout=8.0)
            if resp.status_code == 200:
                return {"available": True, "status_code": 200, "data": resp.json()}
            return {"available": False, "status_code": resp.status_code}
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    def _expiry_key(self, profile: str) -> str:
        return f"{profile}:expires_at"

    def _store_expiry(self, profile: str, *, minutes: int) -> None:
        # Store expiry metadata in profile payload.
        data = self.profiles.load()
        if profile in data.get("profiles", {}):
            data["profiles"][profile]["access_token_expires_at"] = (
                datetime.now(tz=UTC) + timedelta(minutes=minutes)
            ).isoformat()
            self.profiles.save(data)

    def _expires_soon(self, profile: str) -> bool:
        data = self.profiles.load()
        value = data.get("profiles", {}).get(profile, {}).get("access_token_expires_at")
        if not isinstance(value, str):
            return False
        try:
            expires_at = datetime.fromisoformat(value)
            return expires_at <= datetime.now(tz=UTC) + timedelta(minutes=5)
        except Exception:
            return False
