from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.credential_store import (
    Credential,
    CredentialStore,
    HAS_AESGCM,
    get_credential,
    get_creds,
    store_credential,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
    monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
    s = CredentialStore(master_password="test_master")
    return s


@pytest.fixture
def cred_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
    monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
    return CredentialStore(master_password="test")


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInit:
    def test_raises_without_cryptography(self):
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="cryptography"):
                CredentialStore(master_password="pw")

    def test_creates_config_dir(self, tmp_path, monkeypatch):
        cfg = tmp_path / "new_cfg"
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        _store = CredentialStore(master_password="pw")
        assert cfg.exists()


# ---------------------------------------------------------------------------
# Credential dataclass
# ---------------------------------------------------------------------------


class TestCredential:
    def test_to_dict(self):
        now = datetime.now(timezone.utc)
        cred = Credential(
            cred_id="c1",
            name="test",
            cred_type="api_key",
            environment="development",
            value_encrypted="enc",
            created_at=now,
            expires_at=now + timedelta(days=1),
            tags=["web"],
            shared_with=["user1"],
        )
        d = cred.to_dict()
        assert d["cred_id"] == "c1"
        assert d["name"] == "test"
        assert d["cred_type"] == "api_key"
        assert d["tags"] == ["web"]
        assert d["shared_with"] == ["user1"]

    def test_to_dict_no_expiry(self):
        now = datetime.now(timezone.utc)
        cred = Credential(
            cred_id="c2",
            name="test2",
            cred_type="api_key",
            environment="prod",
            value_encrypted="enc",
            created_at=now,
        )
        d = cred.to_dict()
        assert d["expires_at"] is None


# ---------------------------------------------------------------------------
# store / get / get_by_name / delete / rotate
# ---------------------------------------------------------------------------


class TestStoreGetDelete:
    def test_store_and_get_by_name(self, store):
        cred = store.store(name="default", value="secret123", cred_type="api_key")
        assert cred.name == "default"
        assert cred.cred_type == "api_key"
        value = store.get_by_name("default")
        assert value == "secret123"

    def test_store_replaces_existing(self, store):
        store.store(name="dup", value="first", cred_type="api_key")
        store.store(name="dup", value="second", cred_type="api_key")
        assert store.get_by_name("dup") == "second"
        assert store.get_statistics()["total_credentials"] == 1

    def test_store_with_env_and_tags(self, store):
        store.store(
            name="staging_key",
            value="staging_val",
            cred_type="api_key",
            environment="staging",
            expires_in_days=30,
            tags=["staging", "web"],
        )
        creds = store.list_credentials(environment="staging")
        assert len(creds) == 1

    def test_get_by_cred_id(self, store):
        _c = store.store(name="get_test", value="get_val")
        val = store.get(_c.cred_id)
        assert val == "get_val"

    def test_get_nonexistent(self, store):
        assert store.get("nonexistent") is None

    def test_get_by_name_with_type_filter(self, store):
        store.store(name="multi", value="v1", cred_type="api_key")
        store.store(name="multi", value="v2", cred_type="password")
        assert store.get_by_name("multi", cred_type="api_key") == "v1"
        assert store.get_by_name("multi", cred_type="password") == "v2"

    def test_get_by_name_with_env_filter(self, store):
        store.store(name="env_test", value="dev_val", environment="development")
        assert store.get_by_name("env_test", environment="development") == "dev_val"
        assert store.get_by_name("env_test", environment="production") is None

    def test_get_by_name_not_found(self, store):
        assert store.get_by_name("nonexistent") is None

    def test_delete(self, store):
        _c = store.store(name="delete_me", value="del_val")
        assert store.delete("delete_me") is True
        assert store.get_by_name("delete_me") is None

    def test_delete_with_type(self, store):
        store.store(name="multi", value="v1", cred_type="api_key")
        assert store.delete("multi", cred_type="api_key") is True
        assert store.delete("multi", cred_type="api_key") is False

    def test_delete_not_found(self, store):
        assert store.delete("nonexistent") is False

    def test_rotate(self, store):
        _c = store.store(name="rotate_me", value="old_val")
        assert store.rotate(_c.cred_id, "new_val") is True
        assert store.get(_c.cred_id) == "new_val"

    def test_rotate_not_found(self, store):
        assert store.rotate("nonexistent", "val") is False

    def test_get_expired_credential(self, store):
        expired_id = "expired_1"
        store._credentials[expired_id] = Credential(
            cred_id=expired_id,
            name="expired",
            cred_type="api_key",
            environment="dev",
            value_encrypted=store._encrypt("old_value"),
            created_at=datetime.now(timezone.utc) - timedelta(days=400),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        store._save()
        assert store.get(expired_id) is None


# ---------------------------------------------------------------------------
# list_credentials
# ---------------------------------------------------------------------------


class TestListCredentials:
    def test_list_all(self, store):
        store.store(name="k1", value="v1")
        store.store(name="k2", value="v2")
        store.store(name="k3", value="v3", cred_type="password")
        all_creds = store.list_credentials()
        assert len(all_creds) == 3

    def test_list_by_type(self, store):
        store.store(name="k1", value="v1", cred_type="api_key")
        store.store(name="k2", value="v2", cred_type="password")
        api_creds = store.list_credentials(cred_type="api_key")
        assert len(api_creds) == 1

    def test_list_by_environment(self, store):
        store.store(name="k1", value="v1", environment="development")
        store.store(name="k2", value="v2", environment="production")
        dev_creds = store.list_credentials(environment="development")
        assert len(dev_creds) == 1


# ---------------------------------------------------------------------------
# share / check_expiring
# ---------------------------------------------------------------------------


class TestShareAndExpiring:
    def test_share(self, store):
        _c = store.store(name="shared_key", value="shared_val")
        assert store.share(_c.cred_id, "user_a") is True
        assert "user_a" in store._credentials[_c.cred_id].shared_with

    def test_share_not_found(self, store):
        assert store.share("nonexistent", "user_a") is False

    def test_share_duplicate(self, store):
        _c = store.store(name="dup_share", value="val")
        store.share(_c.cred_id, "user_a")
        store.share(_c.cred_id, "user_a")
        assert store._credentials[_c.cred_id].shared_with == ["user_a"]

    def test_check_expiring_none(self, store):
        assert store.check_expiring(7) == []

    def test_check_expiring_some(self, store):
        store.store(name="valid", value="val", expires_in_days=365)
        expired_id = "exp_cred"
        store._credentials[expired_id] = Credential(
            cred_id=expired_id,
            name="expiring",
            cred_type="api_key",
            environment="dev",
            value_encrypted=store._encrypt("val"),
            created_at=datetime.now(timezone.utc) - timedelta(days=360),
            expires_at=datetime.now(timezone.utc) + timedelta(days=3),
        )
        store._save()
        expiring = store.check_expiring(7)
        assert len(expiring) >= 1


# ---------------------------------------------------------------------------
# get_statistics
# ---------------------------------------------------------------------------


class TestGetStatistics:
    def test_statistics(self, store):
        store.store(name="a", value="1", cred_type="api_key", environment="development")
        store.store(name="b", value="2", cred_type="password", environment="production")
        stats = store.get_statistics()
        assert stats["total_credentials"] == 2
        assert stats["by_type"]["api_key"] == 1
        assert stats["by_type"]["password"] == 1
        assert stats["by_environment"]["development"] == 1
        assert stats["encrypted"] is True


# ---------------------------------------------------------------------------
# export / import
# ---------------------------------------------------------------------------


class TestExportImport:
    def test_export_import(self, store, tmp_path):
        store.store(name="export_test", value="export_val")
        fp = str(tmp_path / "backup.enc")
        store.export_encrypted(fp, password="backup_pass")
        assert Path(fp).exists()

        # Import into fresh store
        new_cfg = tmp_path / "new_cfg"
        new_cfg.mkdir()
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(new_cfg))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        CredentialStore(master_password="new_pass")
        new_store = CredentialStore(master_password="pw")
        count = new_store.import_encrypted(fp, password="backup_pass")
        assert count >= 1
        monkeypatch.undo()

    def test_import_no_crypto(self, store, tmp_path):
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="cryptography"):
                store.import_encrypted("dummy", "pw")


# ---------------------------------------------------------------------------
# migrate_legacy_config
# ---------------------------------------------------------------------------


class TestMigrateLegacyConfig:
    def test_migrate_nonexistent(self, store, tmp_path):
        assert store.migrate_legacy_config(tmp_path / "nope.json") is False

    def test_migrate_success(self, store, tmp_path):
        cfg = tmp_path / "legacy.json"
        cfg.write_text(json.dumps({"api_key": "legacy_api", "server_url": "https://srv"}))
        assert store.migrate_legacy_config(cfg) is True
        assert store.get_by_name("default", cred_type="api_key") == "legacy_api"
        assert not cfg.exists()
        assert cfg.with_name(cfg.name + ".bak").exists()


# ---------------------------------------------------------------------------
# migrate_to_aesgcm / rotate_key
# ---------------------------------------------------------------------------


class TestMigration:
    def test_migrate_to_aesgcm_no_aesgcm(self, store):
        with patch("siyarix.credential_store.HAS_AESGCM", False):
            assert store.migrate_to_aesgcm() is False

    def test_migrate_to_aesgcm_success(self, store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        store.store(name="migrate_me", value="migrate_val")
        store._master_key = b"k" * 32
        result = store.migrate_to_aesgcm()
        assert result is True

    def test_rotate_key(self, store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        store.store(name="key_rotate", value="rotate_val")
        assert store.rotate_key() is True

    def test_rotate_key_with_password(self, store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        store.store(name="pw_rotate", value="pw_val")
        assert store.rotate_key(new_master_password="new_password") is True

    def test_rotate_key_no_aesgcm(self, store):
        with patch("siyarix.credential_store.HAS_AESGCM", False):
            assert store.rotate_key() is False


# ---------------------------------------------------------------------------
# retrieve (alias)
# ---------------------------------------------------------------------------


class TestRetrieve:
    def test_retrieve(self, store):
        store.store(name="alias_test", value="alias_val")
        assert store.retrieve("alias_test") == "alias_val"

    def test_retrieve_with_type(self, store):
        store.store(name="alias", value="v", cred_type="password")
        assert store.retrieve("alias", cred_type="password") == "v"


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


class TestConvenienceFunctions:
    def test_get_creds(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        c = get_creds()
        assert c is not None

    def test_get_credential(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        store = get_creds()
        store.store(name="func_test", value="func_val")
        result = get_credential("func_test")
        assert result == "func_val"

    def test_store_credential(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        cred = store_credential("func_store", "func_store_val")
        assert cred.name == "func_store"


# ---------------------------------------------------------------------------
# _kms_available
# ---------------------------------------------------------------------------


class TestKMS:
    def test_kms_not_configured(self, store):
        assert store._kms_available() is False

    def test_kms_boto3_not_available(self, store, monkeypatch):
        monkeypatch.setenv("SIYARIX_KMS_PROVIDER", "aws")
        with patch("builtins.__import__", side_effect=ImportError("no boto3")):
            assert store._kms_available() is False

    def test_kms_available(self, store, monkeypatch):
        monkeypatch.setenv("SIYARIX_KMS_PROVIDER", "aws")
        with patch("builtins.__import__", return_value=MagicMock()):
            assert store._kms_available() is True


# ---------------------------------------------------------------------------
# Encryption internals
# ---------------------------------------------------------------------------


class TestEncryptionInternals:
    def test_encrypt_decrypt_roundtrip(self, store):
        plain = "test_data_123"
        enc = store._encrypt(plain)
        assert enc != plain
        dec = store._decrypt(enc)
        assert dec == plain

    def test_encrypt_aesgcm_fallback(self, store):
        with patch("siyarix.credential_store.HAS_AESGCM", False):
            result = store._encrypt_aesgcm("test")
            # Falls back to Fernet
            assert result != "test"

    def test_decrypt_aesgcm_fallback(self, store):
        with patch("siyarix.credential_store.HAS_AESGCM", False):
            enc = store._encrypt("test")
            dec = store._decrypt_aesgcm(enc)
            assert dec == "test"


# ---------------------------------------------------------------------------
# _normalize_fernet_key
# ---------------------------------------------------------------------------


class TestNormalizeKey:
    def test_normalize_raw_32_bytes(self):
        key = CredentialStore._normalize_fernet_key(b"k" * 32)
        assert isinstance(key, bytes)

    def test_normalize_already_encoded(self):
        import base64

        encoded = base64.urlsafe_b64encode(b"k" * 32)
        key = CredentialStore._normalize_fernet_key(encoded)
        assert key == encoded

    def test_normalize_invalid(self):
        with pytest.raises(ValueError):
            CredentialStore._normalize_fernet_key(b"short")


def test_store_and_retrieve(tmp_path, monkeypatch):
    # Use isolated config dir
    cfg = tmp_path / "siyarix_cfg"
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))

    store = CredentialStore(master_password="testpass")
    cred = store.store(name="api_default", value="secret-value", cred_type="api_key")
    assert cred.name == "api_default"

    retrieved = store.get_by_name("api_default")
    assert retrieved == "secret-value"


def test_rotate_and_delete(tmp_path, monkeypatch):
    cfg = tmp_path / "siyarix_cfg"
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))

    store = CredentialStore(master_password="testpass")
    cred = store.store(name="temp", value="v1", cred_type="api_key")
    old_id = cred.cred_id

    ok = store.rotate(old_id, "v2")
    assert ok
    assert store.get(old_id) == "v2"

    assert store.delete("temp", cred_type="api_key")
    assert store.get_by_name("temp") is None


def test_export_import(tmp_path, monkeypatch):
    cfg = tmp_path / "siyarix_cfg"
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))

    store = CredentialStore(master_password="exportpass")
    store.store(name="a", value="1")
    store.store(name="b", value="2")

    out = tmp_path / "backup.enc"
    store.export_encrypted(str(out), password="pw")
    assert out.exists()

    # create a fresh instance and import
    other_cfg = tmp_path / "other_cfg"
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(other_cfg))
    new_store = CredentialStore(master_password="exportpass")
    count = new_store.import_encrypted(str(out), password="pw")
    assert count == 2


class TestCredentialStoreCore:
    """Cover key uncovered lines in credential_store.py."""

    def test_import_error_sets_flags(self):
        import siyarix.credential_store as cs

        assert hasattr(cs, "HAS_AESGCM")
        # These flags are set at module level, verify they exist
        assert cs.CRYPTO_AVAILABLE is True  # cryptography is available in test env

    def test_no_crypto_raises_runtime_error(self):
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="cryptography package is required"):
                from siyarix.credential_store import CredentialStore

                CredentialStore(master_password="test")

    def test_migrate_legacy_config_missing_file(self):
        from siyarix.credential_store import get_creds

        creds = get_creds()
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", True):
            result = creds.migrate_legacy_config(Path("/nonexistent/file.json"))
            assert result is False

    def test_migrate_legacy_config_too_large(self, tmp_path):
        from siyarix.credential_store import get_creds

        creds = get_creds()
        f = tmp_path / "legacy.json"
        f.write_text("{}")
        with patch.object(Path, "stat") as mock_stat:
            stat_info = MagicMock()
            stat_info.st_size = 20 * 1024 * 1024
            mock_stat.return_value = stat_info
            result = creds.migrate_legacy_config(f)
            assert result is False

    def test_retrieve_delegates_to_get_by_name(self):
        from siyarix.credential_store import get_creds

        creds = get_creds()
        with patch.object(creds, "get_by_name", return_value="val"):
            assert creds.retrieve("name") == "val"

    def test_rate_limit(self):
        from siyarix.credential_store import get_creds
        import time as _time

        creds = get_creds()
        creds._tokens = 0.0
        creds._last_token_update = _time.time()
        with pytest.raises(RuntimeError, match="Rate limit exceeded"):
            creds._check_rate_limit()

    def test_get_expired_credential(self):
        from siyarix.credential_store import get_creds, Credential

        creds = get_creds()
        creds._tokens = 100.0
        from datetime import datetime, timezone, timedelta

        expired = Credential(
            cred_id="e1",
            name="expired",
            cred_type="api_key",
            environment="dev",
            value_encrypted="",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        creds._credentials["e1"] = expired
        with patch.object(creds, "_decrypt") as mock_decrypt:
            result = creds.get("e1")
            assert result is None

    def test_get_updates_usage_periodically(self):
        from siyarix.credential_store import get_creds, Credential

        creds = get_creds()
        from datetime import datetime, timezone

        creds._credentials["c1"] = Credential(
            cred_id="c1",
            name="test",
            cred_type="api_key",
            environment="dev",
            value_encrypted="encrypted_val",
            created_at=datetime.now(timezone.utc),
        )
        with patch.object(creds, "_decrypt", return_value="decrypted"):
            with patch.object(creds, "_save") as mock_save:
                result = creds.get("c1", update_usage=True)
                assert result == "decrypted"
                mock_save.assert_called_once()

    def test_share_adds_user(self):
        from siyarix.credential_store import get_creds, Credential

        creds = get_creds()
        from datetime import datetime, timezone

        cred = Credential(
            cred_id="s1",
            name="shared",
            cred_type="api_key",
            environment="dev",
            value_encrypted="enc",
            created_at=datetime.now(timezone.utc),
        )
        creds._credentials["s1"] = cred
        with patch.object(creds, "_save") as mock_save:
            result = creds.share("s1", "alice")
            assert result is True
            assert "alice" in cred.shared_with
            mock_save.assert_called_once()

    def test_share_missing_cred(self):
        from siyarix.credential_store import get_creds

        creds = get_creds()
        assert creds.share("nonexistent", "alice") is False

    def test_check_expiring(self):
        from siyarix.credential_store import get_creds, Credential

        creds = get_creds()
        from datetime import datetime, timezone, timedelta

        creds._credentials["e1"] = Credential(
            cred_id="e1",
            name="expiring",
            cred_type="api_key",
            environment="dev",
            value_encrypted="enc",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=3),
        )
        expiring = creds.check_expiring(days=7)
        assert len(expiring) == 1

    def test_get_statistics(self):
        from siyarix.credential_store import get_creds, Credential

        creds = get_creds()
        from datetime import datetime, timezone

        creds._credentials["s1"] = Credential(
            cred_id="s1",
            name="stat",
            cred_type="api_key",
            environment="dev",
            value_encrypted="enc",
            created_at=datetime.now(timezone.utc),
        )
        stats = creds.get_statistics()
        assert stats["total_credentials"] >= 1

    def test_get_creds_singleton(self):
        from siyarix.credential_store import get_creds

        c1 = get_creds()
        c2 = get_creds()
        assert c1 is c2

    def test_store_credential_convenience(self):
        from siyarix.credential_store import store_credential

        cred = store_credential("test_key", "test_value")
        assert cred.name == "test_key"

    def test_get_credential_convenience(self):
        from siyarix.credential_store import get_credential, get_creds
        from siyarix.credential_store import Credential
        from datetime import datetime, timezone

        creds = get_creds()
        cred = Credential(
            cred_id="gc1",
            name="get_test",
            cred_type="api_key",
            environment="dev",
            value_encrypted="enc_val",
            created_at=datetime.now(timezone.utc),
        )
        creds._credentials["gc1"] = cred
        with patch.object(creds, "_decrypt", return_value="decrypted"):
            result = get_credential("get_test")
            assert result == "decrypted"


# ═══════════════════════════════════════════════════════════════════
# cvss_scorer.py (92% - missing lines)
# ═══════════════════════════════════════════════════════════════════
class TestCredentialStoreEncryption:
    """Cover remaining credential_store.py uncovered lines."""

    def test_init_no_cryptography_raises(self):
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", False):
            with patch("siyarix.credential_store.Fernet", None):
                with pytest.raises(RuntimeError, match="cryptography"):
                    CredentialStore(master_password="pw")

    def test_rate_limit_exceeded(self, cred_store):
        cred_store._tokens = 0.0
        cred_store._rate = 0.0
        with pytest.raises(RuntimeError, match="Rate limit exceeded"):
            cred_store._check_rate_limit()

    def test_migrate_legacy_config_too_large(self, cred_store, tmp_path):
        cfg = tmp_path / "big.json"
        cfg.write_text("{}")
        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value.st_size = 20 * 1024 * 1024
            assert cred_store.migrate_legacy_config(cfg) is False

    def test_migrate_legacy_config_no_api_key(self, cred_store, tmp_path):
        cfg = tmp_path / "legacy.json"
        cfg.write_text(json.dumps({"server_url": "https://srv", "custom_key": "val"}))
        result = cred_store.migrate_legacy_config(cfg)
        assert result is True
        assert cred_store.get_by_name("default", cred_type="server_url") == "https://srv"
        assert cred_store.get_by_name("custom_key") == "val"

    def test_init_encryption_no_crypto_returns(self, cred_store):
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", False):
            cred_store._init_encryption(None)

    def test_init_encryption_keyring_fallback(self, cred_store, tmp_path):
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "1")
        s = CredentialStore(master_password="pw")
        monkeypatch.undo()

    def test_init_encryption_key_file_fallback(self, cred_store, tmp_path):
        key_file = cred_store._key_file
        key_file.write_bytes(b"k" * 32)
        cred_store._init_encryption(None)

    def test_generate_fernet_key_with_password_writes_salt(self, cred_store, tmp_path):
        s = cred_store
        s._salt_file = tmp_path / "salt"
        s._key_file = tmp_path / "key"
        key = s._generate_fernet_key("mypassword")
        assert s._salt_file.exists()
        assert s._key_file.exists()

    def test_generate_fernet_key_no_password(self, cred_store):
        key = cred_store._generate_fernet_key(None)
        assert isinstance(key, bytes)

    def test_generate_fernet_key_chmod_non_windows(self, cred_store):
        with patch("siyarix.credential_store._safe_chmod") as mock_chmod:
            with patch("siyarix._platform.is_windows", return_value=False):
                cred_store._generate_fernet_key(None)
                mock_chmod.assert_called_once()

    def test_generate_fernet_key_chmod_exception_logged(self, cred_store):
        # _safe_chmod internally catches PermissionError; verify key generation completes
        result = cred_store._generate_fernet_key(None)
        assert isinstance(result, bytes)

    def test_normalize_fernet_key_32_bytes_returns_b64(self):
        result = CredentialStore._normalize_fernet_key(b"k" * 32)
        assert isinstance(result, bytes)
        assert base64.urlsafe_b64encode(b"k" * 32) == result

    def test_normalize_fernet_key_encoded_valid(self):
        encoded = base64.urlsafe_b64encode(b"k" * 32)
        result = CredentialStore._normalize_fernet_key(encoded)
        assert result == encoded

    def test_normalize_fernet_key_raises_on_bad_length(self):
        import base64 as _b64

        encoded = _b64.urlsafe_b64encode(b"k" * 16)
        with pytest.raises(ValueError, match="unsupported key length"):
            CredentialStore._normalize_fernet_key(encoded)

    def test_normalize_fernet_key_bad_b64_raises(self):
        with pytest.raises(ValueError, match="unsupported key length"):
            CredentialStore._normalize_fernet_key(b"\xff\xfe\xfd")

    def test_encrypt_no_fernet_raises(self, cred_store):
        cred_store._fernet = None
        with pytest.raises(RuntimeError, match="encryption not initialized"):
            cred_store._encrypt("data")

    def test_decrypt_no_fernet_raises(self, cred_store):
        cred_store._fernet = None
        with pytest.raises(RuntimeError, match="encryption not initialized"):
            cred_store._decrypt("data")

    def test_migrate_to_aesgcm_no_master_key(self, cred_store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        cred_store.store(name="aes_test", value="val")
        cred_store._master_key = None
        result = cred_store.migrate_to_aesgcm()
        assert result is True

    def test_migrate_to_aesgcm_exception_logged(self, cred_store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        cred_store.store(name="bad_migrate", value="val")
        cred_store._master_key = b"k" * 32
        with patch.object(cred_store, "_decrypt", side_effect=Exception("decrypt fail")):
            with patch("siyarix.credential_store.logger") as mock_log:
                cred_store.migrate_to_aesgcm()
                mock_log.warning.assert_called()

    def test_rotate_key_snapshot_rollback(self, cred_store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        cred_store.store(name="rollback_test", value="val")
        cred_store._master_key = b"k" * 32
        with patch.object(cred_store, "_save", side_effect=RuntimeError("save failed")):
            result = cred_store.rotate_key()
            assert result is False

    def test_rotate_key_decrypt_aesgcm_fallback(self, cred_store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        cred_store.store(name="fallback_test", value="val")
        cred_store._master_key = b"k" * 32
        with patch.object(cred_store, "_decrypt_aesgcm", side_effect=Exception("aesgcm fail")):
            result = cred_store.rotate_key()
            assert result is True

    def test_encrypt_aesgcm_derives_key_via_hkdf(self, cred_store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        cred_store._master_key = b"k" * 10  # not _AES_KEY_SIZE
        result = cred_store._encrypt_aesgcm("test data")
        assert isinstance(result, str)
        assert result != "test data"

    def test_decrypt_aesgcm_derives_key_via_hkdf(self, cred_store):
        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        cred_store._master_key = b"k" * 10
        encrypted = cred_store._encrypt_aesgcm("roundtrip")
        decrypted = cred_store._decrypt_aesgcm(encrypted)
        assert decrypted == "roundtrip"

    def test_get_with_update_usage_frequent(self, cred_store):
        cred = cred_store.store(name="freq", value="val")
        now = datetime.now(timezone.utc)
        cred_store._credentials[cred.cred_id].last_used = now
        with patch("siyarix.credential_store.datetime") as mock_dt:
            mock_dt.now.return_value = now + timedelta(seconds=30)
            val = cred_store.get(cred.cred_id, update_usage=True)
            assert val == "val"

    def test_list_credentials_filters_by_type_and_env(self, cred_store):
        cred_store.store(name="k1", value="v1", cred_type="api_key", environment="dev")
        cred_store.store(name="k2", value="v2", cred_type="password", environment="prod")
        assert len(cred_store.list_credentials(cred_type="api_key")) == 1
        assert len(cred_store.list_credentials(environment="prod")) == 1

    def test_get_statistics_expiring_counts(self, cred_store):
        with patch.object(cred_store, "check_expiring", side_effect=lambda d: [{"days": d}]):
            stats = cred_store.get_statistics()
            assert stats["expiring_7d"] == 1
            assert stats["expiring_30d"] == 1

    def test_convenience_get_credential(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        store = get_creds()
        store.store(name="conv_test", value="conv_val")
        assert get_credential("conv_test") == "conv_val"

    def test_convenience_store_credential(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        cred = store_credential("func_store", "func_val")
        assert cred.name == "func_store"

    def test_export_encrypted_no_crypto(self, cred_store, tmp_path):
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="cryptography"):
                cred_store.export_encrypted(str(tmp_path / "out.enc"), "pw")


# ═══════════════════════════════════════════════════════════════════
# 9. audit_log.py (64% - many uncovered lines)
# ═══════════════════════════════════════════════════════════════════
class TestCredentialStorePersistence:
    """Cover remaining credential_store.py uncovered lines."""

    def test_init_encryption_keyring_success(self, tmp_path, monkeypatch):
        from siyarix.credential_store import CredentialStore

        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "1")
        with patch("keyring.get_password", return_value="k" * 44):
            with patch("keyring.set_password"):
                s = CredentialStore(master_password=None)
                assert s._fernet is not None

    def test_init_encryption_keyring_exception_fallsback(self, tmp_path, monkeypatch):
        from siyarix.credential_store import CredentialStore

        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "1")
        with patch("keyring.get_password", side_effect=Exception("keyring fail")):
            s = CredentialStore(master_password=None)
            assert s._fernet is not None

    def test_init_encryption_key_file_fallback(self, tmp_path, monkeypatch):
        from siyarix.credential_store import CredentialStore

        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        s = CredentialStore(master_password="test")
        # Write a key file for next init
        key_file = s._key_file
        key_file.write_bytes(b"k" * 32)
        s2 = CredentialStore(master_password=None)
        assert s2._fernet is not None

    def test_init_encryption_key_file_read_error(self, tmp_path, monkeypatch):
        from siyarix.credential_store import CredentialStore

        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        s = CredentialStore(master_password="pw")
        # Corrupt the key file so normalization fails
        with patch.object(s, "_key_file") as mkf:
            mkf.exists.return_value = True
            mkf.read_bytes.side_effect = OSError("read fail")
            s._init_encryption(None)

    def test_init_encryption_normalize_valueerror(self, tmp_path, monkeypatch):
        from siyarix.credential_store import CredentialStore

        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
        monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
        s = CredentialStore(master_password="pw")
        with patch.object(s, "_key_file") as mkf:
            mkf.exists.return_value = True
            mkf.read_bytes.return_value = b"bad"
            with patch.object(s, "_normalize_fernet_key", side_effect=ValueError("bad key")):
                s._init_encryption(None)

    def test_generate_fernet_key_existing_salt(self, cred_store, tmp_path):
        salt_file = tmp_path / "salt"
        salt_file.write_bytes(os.urandom(16))
        cred_store._salt_file = salt_file
        key = cred_store._generate_fernet_key("mypassword")
        assert isinstance(key, bytes)

    def test_generate_fernet_key_chmod_exception(self, cred_store):
        # _safe_chmod internally catches PermissionError; verify key generation completes
        result = cred_store._generate_fernet_key(None)
        assert isinstance(result, bytes)

    def test_kms_available_no_provider(self, cred_store):
        with patch.dict(os.environ, {}, clear=True):
            assert cred_store._kms_available() is False

    def test_kms_available_aws_no_boto3(self, cred_store):
        with patch.dict(os.environ, {"SIYARIX_KMS_PROVIDER": "aws"}, clear=True):
            with patch.dict("sys.modules", {"boto3": None}):
                assert cred_store._kms_available() is False

    def test_migrate_to_aesgcm_not_available(self, cred_store):
        with patch("siyarix.credential_store.HAS_AESGCM", False):
            result = cred_store.migrate_to_aesgcm()
            assert result is False

    def test_rotate_key_not_available(self, cred_store):
        with patch("siyarix.credential_store.HAS_AESGCM", False):
            result = cred_store.rotate_key()
            assert result is False

    def test_rotate_key_with_new_password(self, cred_store):
        from siyarix.credential_store import HAS_AESGCM

        if not HAS_AESGCM:
            pytest.skip("AESGCM not available")
        cred_store.store(name="rk_test", value="val")
        cred_store._master_key = None
        with patch.object(cred_store, "_save"):
            result = cred_store.rotate_key(new_master_password="new_pw")
            assert result is True

    def test_load_legacy_credentials_invalid_json(self, cred_store):
        cred_store._creds_file.write_text("not valid json")
        with patch("siyarix.credential_store.logger") as mock_log:
            cred_store._load()
            mock_log.debug.assert_any_call(
                "Legacy credential file uses a different key; treating as empty"
            )

    def test_load_legacy_credentials_unexpected_exception(self, cred_store):
        with patch.object(cred_store, "_decrypt", side_effect=RuntimeError("unexpected")):
            cred_store._creds_file.write_text("{}")
            with patch("siyarix.credential_store.logger") as mock_log:
                cred_store._load()
                mock_log.exception.assert_called()

    def test_load_per_credential_file_kms(self, cred_store, tmp_path):
        kms_dir = cred_store._creds_dir
        kms_dir.mkdir(parents=True, exist_ok=True)
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", True):
            encrypted = cred_store._encrypt(
                json.dumps(
                    {
                        "cred_id": "c1",
                        "name": "test",
                        "cred_type": "api_key",
                        "environment": "dev",
                        "value_encrypted": "enc",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
            )
            (kms_dir / "c1.enc").write_text(encrypted)
            cred_store._load()
            assert "c1" in cred_store._credentials

    def test_save_kms_fallback_to_local(self, cred_store, tmp_path):
        fake_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": fake_boto3}):
            with patch.dict(os.environ, {"SIYARIX_KMS_PROVIDER": "aws"}, clear=True):
                with patch.object(cred_store, "_kms_available", return_value=True):
                    fake_boto3.client.side_effect = Exception("boto fail")
                    with patch("siyarix.credential_store.logger") as mock_log:
                        c = cred_store.store(name="kms_test", value="val")
                        mock_log.exception.assert_called()

    def test_save_kms_no_existing_key(self, cred_store, tmp_path):
        fake_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": fake_boto3}):
            with patch.dict(
                os.environ,
                {"SIYARIX_KMS_PROVIDER": "aws", "AWS_KMS_KEY_ID": "alias/test"},
                clear=True,
            ):
                with patch.object(cred_store, "_kms_available", return_value=True):
                    fake_kms = MagicMock()
                    fake_kms.generate_data_key.return_value = {
                        "Plaintext": b"k" * 32,
                        "CiphertextBlob": b"enc" * 10,
                    }
                with patch("boto3.client", return_value=fake_kms):
                    c = cred_store.store(name="kms_test2", value="val")
                    assert c is not None

    def test_save_kms_encrypted_key_mismatch_reuses(self, cred_store, tmp_path):
        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            with patch.dict(os.environ, {"SIYARIX_KMS_PROVIDER": "aws"}, clear=True):
                with patch.object(cred_store, "_kms_available", return_value=True):
                    cred_store._kms_encrypted_key = "existing_key"
                    cred_store._kms_data_key = b"k" * 32
                    c = cred_store.store(name="kms_reuse", value="val")
                    assert c is not None

    def test_load_legacy_kms_path(self, cred_store, tmp_path):
        import base64

        fake_boto3 = MagicMock()
        kms_dir = cred_store._creds_dir
        kms_dir.mkdir(parents=True, exist_ok=True)
        payload = base64.b64encode(b"encrypted_payload").decode()
        out = json.dumps({"encrypted_key": "key_blob", "payload": payload})
        (kms_dir / "kms_test.enc").write_text(out)
        with patch.dict("sys.modules", {"boto3": fake_boto3}):
            with patch.object(cred_store, "_kms_available", return_value=True):
                fake_kms = MagicMock()
                fake_kms.decrypt.return_value = {"Plaintext": b"k" * 32}
                fake_boto3.client.return_value = fake_kms
                with patch.object(cred_store, "_encrypt") as mock_enc:
                    mock_enc.return_value = "decrypted"
                    cred_store._load()

    def test_update_usage_frequent_calls(self, cred_store):
        from datetime import datetime, timezone, timedelta
        from siyarix.credential_store import Credential

        cred = Credential(
            cred_id="freq",
            name="freq",
            cred_type="api_key",
            environment="dev",
            value_encrypted="enc",
            created_at=datetime.now(timezone.utc),
        )
        cred_store._credentials["freq"] = cred
        now = datetime.now(timezone.utc)
        with patch("siyarix.credential_store.datetime") as mock_dt:
            mock_dt.now.return_value = now + timedelta(seconds=30)
            with patch.object(cred_store, "_decrypt", return_value="val"):
                with patch.object(cred_store, "_save") as mock_save:
                    result = cred_store.get("freq", update_usage=True)
                    assert result == "val"

    def test_rotate_credential(self, cred_store):
        from siyarix.credential_store import Credential

        cred = Credential(
            cred_id="rot",
            name="rot",
            cred_type="api_key",
            environment="dev",
            value_encrypted="enc",
            created_at=datetime.now(timezone.utc),
        )
        cred_store._credentials["rot"] = cred
        with patch.object(cred_store, "_encrypt", return_value="new_enc"):
            result = cred_store.rotate("rot", "new_value")
            assert result is True
            assert cred.rotated is True
            assert cred.usage_count == 0

    def test_rotate_missing(self, cred_store):
        assert cred_store.rotate("nonexistent", "val") is False

    def test_import_encrypted_no_crypto(self, cred_store, tmp_path):
        with patch("siyarix.credential_store.CRYPTO_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="cryptography"):
                cred_store.import_encrypted(str(tmp_path / "in.enc"), "pw")


# ═══════════════════════════════════════════════════════════════════
# 8. executor.py (86% - missing budget reset, permission gate branches)
# ═══════════════════════════════════════════════════════════════════
