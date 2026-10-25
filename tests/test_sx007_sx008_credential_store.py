# SPDX-License-Identifier: AGPL-3.0-or-later
"""SX-007 / SX-008: versioned envelopes, AES key persistence, password vault."""

from __future__ import annotations

import pytest

from siyarix.credential_store import (
    HAS_AESGCM,
    CredentialStore,
    _ENVELOPE_V1,
    _ENVELOPE_V2,
)


@pytest.fixture(autouse=True)
def _no_keyring(monkeypatch):
    monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")


class TestSX007VersionedEnvelopes:
    def test_store_uses_versioned_envelope(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "cfg"))
        store = CredentialStore(master_password="correct-horse")
        cred = store.store(name="api", value="super-secret")
        assert cred.value_encrypted.startswith(_ENVELOPE_V2) or cred.value_encrypted.startswith(
            _ENVELOPE_V1
        )
        assert store.get(cred.cred_id) == "super-secret"

    @pytest.mark.skipif(not HAS_AESGCM, reason="AESGCM unavailable")
    def test_aesgcm_migrated_values_decrypt_after_restart(self, tmp_path, monkeypatch):
        cfg = tmp_path / "aes"
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))
        store = CredentialStore(master_password="vault-pass")
        store.store(name="token", value="migrate-me")
        for cred in store._credentials.values():
            plain = store._decrypt(cred.value_encrypted)
            raw = store._fernet.encrypt(plain.encode()).decode()
            cred.value_encrypted = _ENVELOPE_V1 + raw
        assert store.migrate_to_aesgcm() is True
        for cred in store._credentials.values():
            assert cred.value_encrypted.startswith(_ENVELOPE_V2)
        assert store.get_by_name("token") == "migrate-me"

        store2 = CredentialStore(master_password="vault-pass")
        assert store2.get_by_name("token") == "migrate-me"

    @pytest.mark.skipif(not HAS_AESGCM, reason="AESGCM unavailable")
    def test_master_key_persists_across_restart_file_key_mode(self, tmp_path, monkeypatch):
        cfg = tmp_path / "filekey"
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))
        monkeypatch.delenv("SIYARIX_MASTER_PASSWORD", raising=False)
        store = CredentialStore()
        assert store._master_key is not None
        assert store._key_file.exists()
        store.store(name="k", value="file-key-secret")

        store2 = CredentialStore()
        assert store2.get_by_name("k") == "file-key-secret"
        assert store2._master_key == store._master_key


class TestSX008PasswordVault:
    def test_wrong_password_fails_before_and_after_restart(self, tmp_path, monkeypatch):
        cfg = tmp_path / "pw"
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))
        store = CredentialStore(master_password="right-password")
        store.store(name="secret", value="classified")
        assert store.get_by_name("secret") == "classified"
        assert not store._key_file.exists()

        with pytest.raises(RuntimeError, match="wrong password|Failed to unlock"):
            CredentialStore(master_password="wrong-password")

        enc_files = list((cfg / "credentials.d").glob("*.enc"))
        assert enc_files, "wrong password must not wipe vault files"

        store_ok = CredentialStore(master_password="right-password")
        assert store_ok.get_by_name("secret") == "classified"

    def test_password_mode_does_not_write_raw_key(self, tmp_path, monkeypatch):
        cfg = tmp_path / "nokey"
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))
        store = CredentialStore(master_password="only-password")
        store.store(name="x", value="y")
        assert not store._key_file.exists()
        assert store._salt_file.exists()
        assert store._vault_mode == "password"

    def test_file_key_mode_documented_path(self, tmp_path, monkeypatch):
        cfg = tmp_path / "fk"
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))
        monkeypatch.delenv("SIYARIX_MASTER_PASSWORD", raising=False)
        store = CredentialStore()
        assert store._vault_mode == "file_key"
        assert store._key_file.exists()
        store.store(name="dev", value="local-only")
        store2 = CredentialStore()
        assert store2.get_by_name("dev") == "local-only"

    @pytest.mark.skipif(not HAS_AESGCM, reason="AESGCM unavailable")
    def test_migration_rollback_on_failure(self, tmp_path, monkeypatch):
        cfg = tmp_path / "mig"
        monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(cfg))
        store = CredentialStore(master_password="mig-pass")
        store.store(name="keep", value="original")
        for cred in store._credentials.values():
            plain = store._decrypt(cred.value_encrypted)
            cred.value_encrypted = _ENVELOPE_V1 + store._fernet.encrypt(plain.encode()).decode()
        pre_migrate = {cid: c.value_encrypted for cid, c in store._credentials.items()}

        def save_fail(*args, **kwargs):
            raise RuntimeError("disk full")

        store._save = save_fail  # type: ignore[method-assign]
        assert store.migrate_to_aesgcm() is False

        assert {cid: c.value_encrypted for cid, c in store._credentials.items()} == pre_migrate
        assert store.get_by_name("keep") == "original"
        store2 = CredentialStore(master_password="mig-pass")
        assert store2.get_by_name("keep") == "original"
