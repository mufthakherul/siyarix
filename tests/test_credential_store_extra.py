from phalanx.credential_store import CredentialStore


def test_store_and_retrieve(tmp_path, monkeypatch):
    # Use isolated config dir
    cfg = tmp_path / "phalanx_cfg"
    monkeypatch.setenv("PHALANX_CONFIG_DIR", str(cfg))

    store = CredentialStore(master_password="testpass")
    cred = store.store(name="api_default", value="secret-value", cred_type="api_key")
    assert cred.name == "api_default"

    retrieved = store.get_by_name("api_default")
    assert retrieved == "secret-value"


def test_rotate_and_delete(tmp_path, monkeypatch):
    cfg = tmp_path / "phalanx_cfg"
    monkeypatch.setenv("PHALANX_CONFIG_DIR", str(cfg))

    store = CredentialStore(master_password="testpass")
    cred = store.store(name="temp", value="v1", cred_type="api_key")
    old_id = cred.cred_id

    ok = store.rotate(old_id, "v2")
    assert ok
    assert store.get(old_id) == "v2"

    assert store.delete("temp", cred_type="api_key")
    assert store.get_by_name("temp") is None


def test_export_import(tmp_path, monkeypatch):
    cfg = tmp_path / "phalanx_cfg"
    monkeypatch.setenv("PHALANX_CONFIG_DIR", str(cfg))

    store = CredentialStore(master_password="exportpass")
    store.store(name="a", value="1")
    store.store(name="b", value="2")

    out = tmp_path / "backup.enc"
    store.export_encrypted(str(out), password="pw")
    assert out.exists()

    # create a fresh instance and import
    other_cfg = tmp_path / "other_cfg"
    monkeypatch.setenv("PHALANX_CONFIG_DIR", str(other_cfg))
    new_store = CredentialStore(master_password="exportpass")
    count = new_store.import_encrypted(str(out), password="pw")
    assert count == 2
