"""Tests for credential_store.py — CredentialStore (412 stmts, ~53% covered)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
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
        now = datetime.now()
        cred = Credential(
            cred_id="c1", name="test", cred_type="api_key",
            environment="development", value_encrypted="enc",
            created_at=now,
            expires_at=now + timedelta(days=1),
            tags=["web"], shared_with=["user1"],
        )
        d = cred.to_dict()
        assert d["cred_id"] == "c1"
        assert d["name"] == "test"
        assert d["cred_type"] == "api_key"
        assert d["tags"] == ["web"]
        assert d["shared_with"] == ["user1"]

    def test_to_dict_no_expiry(self):
        now = datetime.now()
        cred = Credential(
            cred_id="c2", name="test2", cred_type="api_key",
            environment="prod", value_encrypted="enc", created_at=now,
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
        store.store(name="staging_key", value="staging_val",
                     cred_type="api_key", environment="staging",
                     expires_in_days=30, tags=["staging", "web"])
        creds = store.list_credentials(environment="staging")
        assert len(creds) == 1

    def test_get_by_cred_id(self, store):
        _c = store.store(name="get_test", value="get_val")
        val = store.get(c.cred_id)
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
        assert store.rotate(c.cred_id, "new_val") is True
        assert store.get(c.cred_id) == "new_val"

    def test_rotate_not_found(self, store):
        assert store.rotate("nonexistent", "val") is False

    def test_get_expired_credential(self, store):
        expired_id = "expired_1"
        store._credentials[expired_id] = Credential(
            cred_id=expired_id, name="expired", cred_type="api_key",
            environment="dev", value_encrypted=store._encrypt("old_value"),
            created_at=datetime.now() - timedelta(days=400),
            expires_at=datetime.now() - timedelta(days=1),
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
        assert store.share(c.cred_id, "user_a") is True
        assert "user_a" in store._credentials[c.cred_id].shared_with

    def test_share_not_found(self, store):
        assert store.share("nonexistent", "user_a") is False

    def test_share_duplicate(self, store):
        _c = store.store(name="dup_share", value="val")
        store.share(c.cred_id, "user_a")
        store.share(c.cred_id, "user_a")
        assert store._credentials[c.cred_id].shared_with == ["user_a"]

    def test_check_expiring_none(self, store):
        assert store.check_expiring(7) == []

    def test_check_expiring_some(self, store):
        store.store(name="valid", value="val", expires_in_days=365)
        expired_id = "exp_cred"
        store._credentials[expired_id] = Credential(
            cred_id=expired_id, name="expiring", cred_type="api_key",
            environment="dev", value_encrypted=store._encrypt("val"),
            created_at=datetime.now() - timedelta(days=360),
            expires_at=datetime.now() + timedelta(days=3),
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
