from unittest.mock import patch

import pytest

from siyarix.auth import AuthManager


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture
def auth(monkeypatch, tmp_path):
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("SIYARIX_MASTER_PASSWORD", "test-password")
    return AuthManager()


class TestAuthManager:
    def test_login_requires_credential(self, auth):
        with pytest.raises(ValueError, match="api_key or access_token"):
            auth.login(profile="test", server_url="http://localhost:8000")

    def test_login_with_api_key(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200, {"token": "abc"})), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok"})):
            result = auth.login(
                profile="staging",
                server_url="http://localhost:8000",
                api_key="api-123",
                org_id="org-demo",
            )
        assert result["profile"] == "staging"
        assert result["auth_method"] == "api_key"
        assert result["health"]["ok"] is True
        assert auth.credentials.retrieve("staging", "api_key") == "api-123"

    def test_login_with_access_token(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok"})):
            result = auth.login(
                profile="prod",
                server_url="https://server.example.com",
                access_token="access-tok-123",
                refresh_token="refresh-tok-456",
            )
        assert result["auth_method"] == "token"
        assert auth.credentials.retrieve("prod", "access_token") == "access-tok-123"
        assert auth.credentials.retrieve("prod", "refresh_token") == "refresh-tok-456"

    def test_login_api_key_clears_token(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok"})):
            auth.login(profile="p", server_url="http://localhost", access_token="tok")
            auth.login(profile="p", server_url="http://localhost", api_key="key")
        assert auth.credentials.retrieve("p", "api_key") == "key"
        assert auth.credentials.retrieve("p", "access_token") is None

    def test_logout_clears_credentials(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok"})):
            auth.login(profile="p", server_url="http://localhost", api_key="key")
        auth.logout("p")
        assert auth.credentials.retrieve("p", "api_key") is None
        assert auth.credentials.retrieve("p", "access_token") is None

    def test_status_profile_not_found(self, auth):
        status = auth.status("nonexistent")
        assert status["logged_in"] is False
        assert status["reason"] == "profile_not_found"

    def test_status_logged_out(self, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        status = auth.status("test")
        assert status["logged_in"] is False

    def test_status_logged_in(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok", "email": "agent@test.dev"})):
            auth.login(profile="test", server_url="http://localhost", api_key="key")
        status = auth.status("test")
        assert status["logged_in"] is True
        assert status["auth_method"] == "api_key"

    def test_status_with_token_type(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok"})):
            auth.login(profile="test", server_url="http://localhost", access_token="tok")
        status = auth.status("test")
        assert status["token_type"] == "access_token"
        assert status["has_refresh_token"] is False

    def test_refresh_profile_not_found(self, auth):
        with pytest.raises(ValueError, match="not found"):
            auth.refresh("nonexistent")

    def test_refresh_no_refresh_token(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok"})):
            auth.login(profile="test", server_url="http://localhost", api_key="key")
        with pytest.raises(ValueError, match="Refresh token"):
            auth.refresh("test")

    @patch("siyarix.auth.httpx.post")
    def test_refresh_success(self, mock_post, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        auth.credentials.store("test", "http://localhost", "server_url")
        auth.credentials.store("test", "old-refresh", "refresh_token")
        mock_post.return_value = _Resp(200, {"access_token": "new-token", "refresh_token": "new-refresh", "expires_in": 3600})
        result = auth.refresh("test")
        assert result["status"] == "refreshed"

    @patch("httpx.post")
    def test_refresh_failure_status(self, mock_post, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        auth.credentials.store("test", "http://localhost", "server_url")
        auth.credentials.store("test", "refresh", "refresh_token")
        mock_post.return_value = _Resp(401)
        with pytest.raises(ValueError, match="Token refresh failed"):
            auth.refresh("test")

    @patch("httpx.post")
    def test_refresh_missing_access_token(self, mock_post, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        auth.credentials.store("test", "http://localhost", "server_url")
        auth.credentials.store("test", "refresh", "refresh_token")
        mock_post.return_value = _Resp(200, {})
        with pytest.raises(ValueError, match="missing access_token"):
            auth.refresh("test")

    def test_auth_headers_no_profile(self, auth):
        assert auth.auth_headers("nonexistent") == {}

    def test_auth_headers_bearer(self, auth):
        auth.login(profile="test", server_url="http://localhost", access_token="tok")
        headers = auth.auth_headers("test")
        assert headers["Authorization"] == "Bearer tok"

    def test_auth_headers_api_key(self, auth):
        auth.login(profile="test", server_url="http://localhost", api_key="key")
        headers = auth.auth_headers("test")
        assert headers["X-API-Key"] == "key"

    def test_require_auth_headers_success(self, auth):
        auth.login(profile="test", server_url="http://localhost", api_key="key")
        headers = auth.require_auth_headers("test")
        assert headers["X-API-Key"] == "key"

    def test_require_auth_headers_failure(self, auth):
        with pytest.raises(ValueError, match="no stored credentials"):
            auth.require_auth_headers("test")

    def test_health_success(self, auth):
        with patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok"})):
            result = auth._health("http://localhost", "test")
        assert result["ok"] is True

    def test_health_exception(self, auth):
        with patch("siyarix.auth.httpx.get", side_effect=ConnectionError("timeout")):
            result = auth._health("http://localhost", "test")
            assert result["ok"] is False
            assert "timeout" in result["error"]

    def test_me_no_headers(self, auth):
        result = auth._me("http://localhost", "nonexistent")
        assert result["available"] is False

    def test_me_success(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", return_value=_Resp(200, {"status": "ok", "email": "agent@test.dev"})):
            auth.login(profile="test", server_url="http://localhost", api_key="key")
            result = auth._me("http://localhost", "test")
        assert result["available"] is True

    @patch("siyarix.auth.httpx.get")
    def test_me_http_error(self, mock_get, auth):
        auth.login(profile="test", server_url="http://localhost", api_key="key")
        mock_get.return_value = _Resp(403)
        result = auth._me("http://localhost", "test")
        assert result["available"] is False
        assert result["status_code"] == 403

    def test_me_exception(self, auth):
        with patch("siyarix.auth.httpx.post", return_value=_Resp(200)), \
             patch("siyarix.auth.httpx.get", side_effect=ConnectionError("timeout")):
            auth.login(profile="test", server_url="http://localhost", api_key="key")
            result = auth._me("http://localhost", "test")
            assert result["available"] is False
            assert "timeout" in result["error"]
        with patch("httpx.get", side_effect=ConnectionError("dns fail")):
            result = auth._me("http://localhost", "test")
            assert result["available"] is False
            assert "dns fail" in result.get("error", "")

    def test_expiry_key(self, auth):
        assert auth._expiry_key("test") == "test:expires_at"

    def test_store_expiry(self, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        auth._store_expiry("test", minutes=60)
        data = auth.profiles.load()
        expires = data["profiles"]["test"].get("access_token_expires_at")
        assert expires is not None

    def test_store_expiry_no_profile(self, auth):
        auth._store_expiry("test", minutes=60)
        data = auth.profiles.load()
        assert "access_token_expires_at" not in data["profiles"].get("test", {})

    def test_expires_soon_no_value(self, auth):
        assert auth._expires_soon("test") is False

    def test_expires_soon_future(self, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        from datetime import UTC, datetime, timedelta
        data = auth.profiles.load()
        expires = (datetime.now(tz=UTC) + timedelta(hours=2)).isoformat()
        data["profiles"]["test"]["access_token_expires_at"] = expires
        auth.profiles.save(data)
        assert auth._expires_soon("test") is False

    def test_expires_soon_parse_error(self, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        data = auth.profiles.load()
        data["profiles"]["test"]["access_token_expires_at"] = "not-a-date"
        auth.profiles.save(data)
        assert auth._expires_soon("test") is False

    def test_auth_headers_with_auto_refresh(self, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        auth.credentials.store("test", "http://localhost", "server_url")
        auth.credentials.store("test", "old-token", "access_token")
        auth.credentials.store("test", "refresh-tok", "refresh_token")
        headers = auth.auth_headers("test", auto_refresh=True)
        assert "Authorization" in headers or "X-API-Key" in headers

    def test_refresh_with_expires_in_zero(self, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        auth.credentials.store("test", "http://localhost", "server_url")
        auth.credentials.store("test", "refresh", "refresh_token")
        with patch("httpx.post", return_value=_Resp(200, {"access_token": "new-tok", "expires_in": 0})):
            result = auth.refresh("test")
            assert result["status"] == "refreshed"

    def test_refresh_without_new_refresh_token(self, auth):
        auth.profiles.upsert_profile("test", server_url="http://localhost")
        auth.credentials.store("test", "http://localhost", "server_url")
        auth.credentials.store("test", "old-refresh", "refresh_token")
        with patch("httpx.post", return_value=_Resp(200, {"access_token": "new-tok"})):
            result = auth.refresh("test")
            assert result["status"] == "refreshed"
            assert auth.credentials.retrieve("test", "refresh_token") == "old-refresh"
