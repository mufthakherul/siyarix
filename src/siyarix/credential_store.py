# SPDX-License-Identifier: AGPL-3.0-or-later

"""Secure Credential & API Key Management.

Encrypted credential storage using Fernet / AES-256-GCM with optional
KMS envelope encryption and OS keyring integration.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from siyarix.config import get_config_dir

HAS_AESGCM = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    HAS_AESGCM = True
    CRYPTO_AVAILABLE = True
except ImportError:
    Fernet = None  # type: ignore
    hashes = None  # type: ignore
    AESGCM = None  # type: ignore
    PBKDF2HMAC = None  # type: ignore
    CRYPTO_AVAILABLE = False
    HAS_AESGCM = False

logger = logging.getLogger(__name__)

if not CRYPTO_AVAILABLE:
    logger.warning(
        "cryptography package not installed. Credential encryption unavailable; "
        "CredentialStore will be disabled until cryptography is installed."
    )

# AES-256-GCM key derivation constants
_AES_KEY_SIZE = 32  # 256 bits
_AES_NONCE_SIZE = 12  # 96 bits recommended for GCM
_AES_ITERATIONS = 600000  # OWASP recommended PBKDF2 iterations


class CredentialType(StrEnum):
    """Credential types"""

    PASSWORD = "password"  # nosec B105
    API_KEY = "api_key"
    TOKEN = "token"  # nosec B105
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"
    AWS_KEY = "aws_key"
    AZURE_SP = "azure_sp"
    GCP_SA = "gcp_sa"
    SERVER_URL = "server_url"


class Environment(StrEnum):
    """Environments"""

    DEV = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    ALL = "all"


@dataclass
class Credential:
    """Stored credential"""

    cred_id: str
    name: str
    cred_type: str
    environment: str
    value_encrypted: str
    created_at: datetime
    expires_at: datetime | None = None
    last_used: datetime | None = None
    usage_count: int = 0
    rotated: bool = False
    tags: list[str] = field(default_factory=list)
    shared_with: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cred_id": self.cred_id,
            "name": self.name,
            "cred_type": self.cred_type,
            "environment": self.environment,
            "value_encrypted": self.value_encrypted,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "usage_count": self.usage_count,
            "rotated": self.rotated,
            "tags": self.tags,
            "shared_with": self.shared_with,
        }


class CredentialStore:
    """Enterprise credential store"""

    _DEFAULT_CONFIG_DIR = get_config_dir()
    _SECRET_PATH = _DEFAULT_CONFIG_DIR / "credentials.json"

    def __init__(self, master_password: str | None = None) -> None:
        self._config_dir = Path(os.getenv("SIYARIX_CONFIG_DIR", str(self._DEFAULT_CONFIG_DIR)))
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._creds_dir = self._config_dir / "credentials.d"
        self._creds_dir.mkdir(parents=True, exist_ok=True)
        self._creds_file = self._config_dir / "credentials.enc"
        self._key_file = self._config_dir / ".cred_store_key"
        self._salt_file = self._config_dir / ".cred_store_salt"
        self._credentials: dict[str, Credential] = {}
        self._master_key: bytes | None = None
        self._fernet: Any = None
        self._nonce_counter = int(time.time() * 1000) & 0xFFFFFFFF
        self._nonce_lock = threading.Lock()
        self._kms_data_key: bytes | None = None
        self._kms_encrypted_key: str | None = None

        # Enforce cryptography for secure credential handling. Fail fast if missing.
        if not CRYPTO_AVAILABLE:
            raise RuntimeError(
                "cryptography package is required for CredentialStore. Install with: pip install cryptography"
            )

        self._init_encryption(master_password)

        self._load()

        self._rate_limit_lock = threading.Lock()
        self._tokens = 100.0
        self._last_token_update = time.time()
        self._rate = 10.0

    def _check_rate_limit(self) -> None:
        with self._rate_limit_lock:
            now = time.time()
            elapsed = now - self._last_token_update
            self._tokens = min(100.0, self._tokens + elapsed * self._rate)
            self._last_token_update = now
            if self._tokens < 1.0:
                raise RuntimeError("Rate limit exceeded")
            self._tokens -= 1.0

    def migrate_legacy_config(self, filepath: Path) -> bool:
        """Migrate legacy JSON config to the credential store format."""
        if not filepath.exists():
            return False

        if filepath.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
            logger.warning("Legacy config file too large to migrate")
            return False

        data = json.loads(filepath.read_text())
        # Reorder to ensure api_key is stored first for retrieve default
        if "api_key" in data:
            self.store(name="default", value=str(data["api_key"]), cred_type="api_key")

        for key, value in data.items():
            if key not in ["api_key", "name"]:
                if key == "server_url":
                    self.store(name="default", value=str(value), cred_type="server_url")
                else:
                    self.store(name=key, value=str(value))

        new_path = filepath.with_name(filepath.name + ".bak")
        filepath.rename(new_path)
        return True

    def retrieve(self, name: str, cred_type: str | None = None) -> str | None:
        return self.get_by_name(name, cred_type=cred_type)

    def _init_encryption(self, password: str | None) -> None:
        """Initialize encryption"""
        if not CRYPTO_AVAILABLE:
            return
        password = password or os.getenv("SIYARIX_MASTER_PASSWORD")

        # Prefer OS keyring when available and enabled. Falls back to local keyfile.
        use_keyring = os.getenv("SIYARIX_USE_KEYRING", "1").strip() not in {
            "0",
            "false",
            "no",
        }
        key_material = None
        if use_keyring:
            try:
                import keyring

                stored = keyring.get_password("siyarix", "cred_store_key")
                if stored:
                    key_material = stored.encode()
            except Exception:
                logger.debug("Keyring unavailable or failed; falling back to file-based key")

        # If no key material from keyring, try local key file
        if key_material is None and self._key_file.exists():
            try:
                key_material = self._key_file.read_bytes()
            except Exception as exc:
                logger.debug("Failed to read key file %s: %s", self._key_file, exc)
                key_material = None

        # Normalize or generate
        if key_material is not None:
            try:
                key = self._normalize_fernet_key(key_material)
            except ValueError:
                logger.warning("Invalid credential store key detected; regenerating a new key")
                key = self._generate_fernet_key(password)
        else:
            key = self._generate_fernet_key(password)

        # If we generated a key and keyring is available, attempt to persist there
        if use_keyring:
            try:
                import keyring

                key_b64 = key.decode() if isinstance(key, bytes) else str(key)
                # store base64 key material in keyring (best-effort)
                keyring.set_password("siyarix", "cred_store_key", key_b64)
            except Exception:
                logger.debug(
                    "Failed to persist credential store key to keyring; key stored locally if permitted"
                )

        self._fernet = Fernet(key)

    def _kms_available(self) -> bool:
        """Return True if a KMS provider is configured and boto3 is available."""
        provider = os.getenv("SIYARIX_KMS_PROVIDER", "").strip().lower()
        if provider != "aws":
            return False
        try:
            __import__("boto3")

            return True
        except Exception:
            return False

    def _generate_fernet_key(self, password: str | None) -> bytes:
        """Create a valid Fernet key and persist the raw material."""
        if password:
            self._config_dir.mkdir(parents=True, exist_ok=True)

            # Use persistent salt (C-01)
            if self._salt_file.exists():
                salt = self._salt_file.read_bytes()
            else:
                salt = os.urandom(16)
                self._salt_file.write_bytes(salt)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=_AES_ITERATIONS,  # C-02: Unify iterations
            )
            raw_key = kdf.derive(password.encode())
        else:
            # Keep startup working in local/dev environments when no password is configured.
            raw_key = os.urandom(32)

        self._config_dir.mkdir(parents=True, exist_ok=True)
        # write raw key material and protect file permissions on POSIX systems
        self._key_file.write_bytes(raw_key)
        try:
            # restrict permissions to owner only where supported
            if os.name != "nt":
                os.chmod(self._key_file, 0o600)
            else:
                logger.warning(
                    "Key file %s is not permission-restricted on Windows", self._key_file
                )
        except Exception as exc:
            # best-effort; log but continue
            logger.exception("Failed to set permissions on credential store key file: %s", exc)
        return base64.urlsafe_b64encode(raw_key)

    @staticmethod
    def _normalize_fernet_key(key_material: bytes) -> bytes:
        """Accept either raw 32-byte key material or a stored Fernet key."""
        if len(key_material) == 32:
            return base64.urlsafe_b64encode(key_material)

        try:
            decoded = base64.urlsafe_b64decode(key_material)
        except Exception as exc:
            raise ValueError("unsupported key format") from exc

        if len(decoded) == 32:
            return key_material

        raise ValueError("unsupported key length")

    def _encrypt_aesgcm(self, data: str) -> str:
        """Encrypt using AES-256-GCM as documented in Chapter 5.4."""
        if not HAS_AESGCM or not self._master_key:
            return self._encrypt(data)
        with self._nonce_lock:
            self._nonce_counter = (self._nonce_counter + 1) & 0xFFFFFFFF
            counter_bytes = self._nonce_counter.to_bytes(4, "big")
        nonce = os.urandom(8) + counter_bytes
        key = self._master_key
        if len(key) != _AES_KEY_SIZE:
            from cryptography.hazmat.primitives import hashes as hash_mod
            from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

            hkdf = HKDFExpand(
                algorithm=hash_mod.SHA256(),
                length=_AES_KEY_SIZE,
                info=b"siyarix-aes-gcm-key",
            )
            key = hkdf.derive(key)
        ct = AESGCM(key).encrypt(nonce, data.encode(), b"siyarix-credential")
        return base64.b64encode(nonce + ct).decode()

    def _decrypt_aesgcm(self, encrypted: str) -> str:
        """Decrypt using AES-256-GCM."""
        if not HAS_AESGCM or not self._master_key:
            return self._decrypt(encrypted)
        raw = base64.b64decode(encrypted)
        nonce = raw[:_AES_NONCE_SIZE]
        ct = raw[_AES_NONCE_SIZE:]
        key = self._master_key
        if len(key) != _AES_KEY_SIZE:
            from cryptography.hazmat.primitives import hashes as hash_mod
            from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

            hkdf = HKDFExpand(
                algorithm=hash_mod.SHA256(),
                length=_AES_KEY_SIZE,
                info=b"siyarix-aes-gcm-key",
            )
            key = hkdf.derive(key)
        return AESGCM(key).decrypt(nonce, ct, b"siyarix-credential").decode()

    def _encrypt(self, data: str) -> str:
        """Encrypt data using Fernet (backward compatible)."""
        if not self._fernet:
            raise RuntimeError("encryption not initialized")
        return self._fernet.encrypt(data.encode()).decode()

    def _decrypt(self, encrypted: str) -> str:
        """Decrypt data using Fernet (backward compatible)."""
        if not self._fernet:
            raise RuntimeError("encryption not initialized")
        return self._fernet.decrypt(encrypted.encode()).decode()

    def migrate_to_aesgcm(self) -> bool:
        """Migrate all credentials from Fernet to AES-256-GCM encryption."""
        if not HAS_AESGCM:
            logger.warning("AES-256-GCM not available; skipping migration")
            return False
        if not self._master_key:
            self._master_key = os.urandom(_AES_KEY_SIZE)
        migrated = 0
        for cred in self._credentials.values():
            try:
                plaintext = self._decrypt(cred.value_encrypted)
                cred.value_encrypted = self._encrypt_aesgcm(plaintext)
                migrated += 1
            except Exception as exc:
                logger.warning("Failed to migrate credential %s: %s", cred.cred_id, exc)
        if migrated > 0:
            self._save()
            logger.info("Migrated %d credentials to AES-256-GCM", migrated)
        return migrated > 0

    def rotate_key(self, new_master_password: str | None = None) -> bool:
        """Rotate master encryption key (Chapter 5.4 key rotation)."""
        if not HAS_AESGCM:
            logger.warning("AES-256-GCM not available for key rotation")
            return False

        # C-03: Atomic rotation - snapshot credentials
        snapshot = {k: Credential(**v.to_dict()) for k, v in self._credentials.items()}

        old_master_key = self._master_key
        self._master_key = os.urandom(_AES_KEY_SIZE)
        if new_master_password:
            # For new master passwords, generate a new salt
            new_salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=_AES_KEY_SIZE,
                salt=new_salt,
                iterations=_AES_ITERATIONS,
            )
            self._master_key = kdf.derive(new_master_password.encode())
            self._salt_file.write_bytes(new_salt)

        # Re-encrypt all credentials with new key
        try:
            for cred in self._credentials.values():
                try:
                    plaintext = (
                        self._decrypt_aesgcm(cred.value_encrypted)
                        if HAS_AESGCM
                        else self._decrypt(cred.value_encrypted)
                    )
                    cred.value_encrypted = self._encrypt_aesgcm(plaintext)
                    cred.rotated = True
                except Exception as exc:
                    logger.debug("AESGCM decrypt failed for %s, falling back to Fernet: %s", cred.cred_id, exc)
                    plaintext = self._decrypt(cred.value_encrypted)
                    cred.value_encrypted = self._encrypt_aesgcm(plaintext)
                    cred.rotated = True

            self._save()
            logger.info("Master key rotated successfully")
            return True
        except Exception as exc:
            # Rollback on partial failure
            self._credentials = snapshot
            self._master_key = old_master_key
            logger.error("Key rotation failed, rolling back. Error: %s", exc)
            return False

    def _load(self) -> None:
        """Load credentials from disk"""
        legacy_loaded = False
        if self._creds_file.exists():
            try:
                raw = self._creds_file.read_text()
                if raw.strip():
                    obj = None
                    try:
                        obj = json.loads(raw)
                    except json.JSONDecodeError:
                        obj = None

                    if obj and isinstance(obj, dict) and "encrypted_key" in obj and "payload" in obj:
                        if not self._kms_available():
                            raise RuntimeError("KMS provider configured but boto3 not available")
                        import base64 as _b64
                        import boto3  # pyright: ignore[reportMissingImports]

                        kms_key_blob = _b64.b64decode(obj["encrypted_key"])
                        payload = _b64.b64decode(obj["payload"])
                        kms = boto3.client("kms")
                        resp = kms.decrypt(CiphertextBlob=kms_key_blob)
                        data_key = resp.get("Plaintext")
                        if not data_key:
                            raise RuntimeError("KMS failed to decrypt data key")
                        fernet_key = base64.urlsafe_b64encode(data_key)
                        f = Fernet(fernet_key)
                        decrypted = f.decrypt(payload).decode()
                        data = json.loads(decrypted)

                        # Cache the KMS data key for future use
                        self._kms_data_key = data_key
                        self._kms_encrypted_key = obj["encrypted_key"]
                    else:
                        decrypted = self._decrypt(raw)
                        data = json.loads(decrypted)

                    for cred_data in data:
                        if "value_encrypted" not in cred_data:
                            logger.error("Credential entry missing value_encrypted")
                        cred = Credential(
                            cred_id=cred_data["cred_id"],
                            name=cred_data["name"],
                            cred_type=cred_data["cred_type"],
                            environment=cred_data["environment"],
                            value_encrypted=cred_data["value_encrypted"],
                            created_at=datetime.fromisoformat(cred_data["created_at"]),
                            expires_at=(
                                datetime.fromisoformat(cred_data["expires_at"])
                                if cred_data.get("expires_at")
                                else None
                            ),
                            last_used=(
                                datetime.fromisoformat(cred_data["last_used"])
                                if cred_data.get("last_used")
                                else None
                            ),
                            usage_count=cred_data.get("usage_count", 0),
                            rotated=cred_data.get("rotated", False),
                            tags=cred_data.get("tags", []),
                            shared_with=cred_data.get("shared_with", []),
                        )
                        self._credentials[cred.cred_id] = cred
                    legacy_loaded = True
            except Exception as exc:
                logger.exception("Failed to load legacy credentials: %s", exc)

        if self._creds_dir.exists():
            for filepath in self._creds_dir.glob("*.enc"):
                try:
                    raw = filepath.read_text()
                    if not raw.strip():
                        continue

                    obj = None
                    try:
                        obj = json.loads(raw)
                    except json.JSONDecodeError:
                        obj = None

                    if obj and isinstance(obj, dict) and "encrypted_key" in obj and "payload" in obj:
                        if not self._kms_available():
                            raise RuntimeError("KMS provider configured but boto3 not available")
                        import base64 as _b64
                        import boto3  # pyright: ignore[reportMissingImports]

                        encrypted_key = obj["encrypted_key"]
                        if self._kms_encrypted_key != encrypted_key or not self._kms_data_key:
                            kms_key_blob = _b64.b64decode(encrypted_key)
                            kms = boto3.client("kms")
                            resp = kms.decrypt(CiphertextBlob=kms_key_blob)
                            self._kms_data_key = resp.get("Plaintext")
                            self._kms_encrypted_key = encrypted_key

                        if not self._kms_data_key:
                            raise RuntimeError("KMS failed to decrypt data key")

                        fernet_key = base64.urlsafe_b64encode(self._kms_data_key)
                        f = Fernet(fernet_key)
                        payload = _b64.b64decode(obj["payload"])
                        decrypted = f.decrypt(payload).decode()
                        data = json.loads(decrypted)
                    else:
                        decrypted = self._decrypt(raw)
                        data = json.loads(decrypted)

                    cred = Credential(
                        cred_id=data["cred_id"],
                        name=data["name"],
                        cred_type=data["cred_type"],
                        environment=data["environment"],
                        value_encrypted=data["value_encrypted"],
                        created_at=datetime.fromisoformat(data["created_at"]),
                        expires_at=(
                            datetime.fromisoformat(data["expires_at"])
                            if data.get("expires_at")
                            else None
                        ),
                        last_used=(
                            datetime.fromisoformat(data["last_used"])
                            if data.get("last_used")
                            else None
                        ),
                        usage_count=data.get("usage_count", 0),
                        rotated=data.get("rotated", False),
                        tags=data.get("tags", []),
                        shared_with=data.get("shared_with", []),
                    )
                    self._credentials[cred.cred_id] = cred
                except Exception as exc:
                    logger.exception("Failed to load credential %s: %s", filepath, exc)

        if legacy_loaded:
            self._save()
            try:
                self._creds_file.rename(self._creds_file.with_name("credentials.enc.bak"))
            except Exception as exc:
                logger.warning("Failed to rename legacy credentials file: %s", exc)

    def _save(self, cred: Credential | None = None, delete_cred_id: str | None = None) -> None:
        """Save credentials to disk incrementally"""
        if delete_cred_id:
            cred_file = self._creds_dir / f"{delete_cred_id}.enc"
            if cred_file.exists():
                cred_file.unlink()

        creds_to_save = [cred] if cred else list(self._credentials.values())
        if not creds_to_save and not delete_cred_id:
            return

        provider = os.getenv("SIYARIX_KMS_PROVIDER", "").strip().lower()
        use_kms = provider == "aws" and self._kms_available()
        fernet_key = None
        f = None

        if use_kms:
            try:
                import base64 as _b64
                import boto3  # pyright: ignore[reportMissingImports]

                if not self._kms_data_key or not self._kms_encrypted_key:
                    kms = boto3.client("kms")
                    key_id = os.getenv("AWS_KMS_KEY_ID")
                    if not key_id:
                        raise RuntimeError("AWS_KMS_KEY_ID must be set when SIYARIX_KMS_PROVIDER=aws")
                    resp = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
                    plaintext = resp.get("Plaintext")
                    ciphertext_blob = resp.get("CiphertextBlob")
                    if not plaintext or not ciphertext_blob:
                        raise RuntimeError("Failed to generate data key from KMS")
                    self._kms_data_key = plaintext
                    self._kms_encrypted_key = _b64.b64encode(ciphertext_blob).decode()

                assert self._kms_data_key is not None, "KMS data key must be set"
                fernet_key = base64.urlsafe_b64encode(self._kms_data_key)
                f = Fernet(fernet_key)
            except Exception:
                logger.exception("KMS envelope encryption failed; falling back to local encryption")
                use_kms = False

        for c in creds_to_save:
            if not c:
                continue
            raw = json.dumps(c.to_dict())
            if use_kms and f and self._kms_encrypted_key:
                payload = f.encrypt(raw.encode())
                out = {
                    "encrypted_key": self._kms_encrypted_key,
                    "payload": _b64.b64encode(payload).decode(),
                }
                content_str = json.dumps(out)
            else:
                content_str = self._encrypt(raw)

            (self._creds_dir / f"{c.cred_id}.enc").write_text(content_str)

    def store(
        self,
        name: str,
        value: str,
        cred_type: str = CredentialType.API_KEY.value,
        environment: str = Environment.DEV.value,
        expires_in_days: int = 365,
        tags: list[str] | None = None,
    ) -> Credential:
        """Store credential"""
        self._check_rate_limit()
        # Replace any existing credential with the same logical name/type.
        self.delete(name, cred_type)
        cred = Credential(
            cred_id=uuid.uuid4().hex,
            name=name,
            cred_type=cred_type,
            environment=environment,
            value_encrypted=self._encrypt(value),
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
            tags=tags or [],
        )
        self._credentials[cred.cred_id] = cred
        self._save()
        return cred

    def get(self, cred_id: str, update_usage: bool = False) -> str | None:
        """Retrieve credential value"""
        self._check_rate_limit()
        cred = self._credentials.get(cred_id)
        if not cred:
            return None

        # Check expiration
        if cred.expires_at and cred.expires_at < datetime.now(timezone.utc):
            logger.warning("Credential %s has expired", cred.name)
            return None

        if update_usage:
            now = datetime.now(timezone.utc)
            # Periodically write usage to avoid IO bottleneck
            if not cred.last_used or (now - cred.last_used).total_seconds() > 60:
                cred.last_used = now
                cred.usage_count += 1
                self._save(cred)
            else:
                cred.last_used = now
                cred.usage_count += 1

        return self._decrypt(cred.value_encrypted)

    def get_by_name(
        self, name: str, environment: str | None = None, cred_type: str | None = None
    ) -> str | None:
        """Get credential by name"""
        for cred in self._credentials.values():
            if cred.name == name:
                if environment and cred.environment != environment:
                    continue
                if cred_type and cred.cred_type != cred_type:
                    continue
                return self.get(cred.cred_id)
        return None

    def list_credentials(
        self, cred_type: str | None = None, environment: str | None = None
    ) -> list[dict]:
        """List credentials (metadata only, no values)"""
        creds: list[Credential] = list(self._credentials.values())

        if cred_type:
            creds = [c for c in creds if c.cred_type == cred_type]
        if environment:
            creds = [c for c in creds if c.environment == environment]

        return [c.to_dict() for c in creds]

    def delete(self, name: str, cred_type: str | None = None) -> bool:
        """Delete credential by name and type"""
        self._check_rate_limit()
        for cred_id, cred in list(self._credentials.items()):
            if cred.name == name and (not cred_type or cred.cred_type == cred_type):
                del self._credentials[cred_id]
                self._save(delete_cred_id=cred_id)
                return True
        return False

    def rotate(self, cred_id: str, new_value: str) -> bool:
        """Rotate credential"""
        cred = self._credentials.get(cred_id)
        if not cred:
            return False

        cred.value_encrypted = self._encrypt(new_value)
        cred.rotated = True
        cred.last_used = None
        cred.usage_count = 0
        self._save(cred)
        return True

    def share(self, cred_id: str, user: str) -> bool:
        """Share credential with team member"""
        cred = self._credentials.get(cred_id)
        if not cred:
            return False

        if user not in cred.shared_with:
            cred.shared_with.append(user)
            self._save(cred)
        return True

    def check_expiring(self, days: int = 7) -> list[dict]:
        """Check for expiring credentials"""
        cutoff = datetime.now(timezone.utc) + timedelta(days=days)
        expiring = []
        for cred in self._credentials.values():
            if cred.expires_at and cred.expires_at <= cutoff:
                expiring.append(cred.to_dict())
        return expiring

    def export_encrypted(self, filepath: str, password: str) -> None:
        """Export encrypted backup"""
        data = [c.to_dict() for c in self._credentials.values()]
        # Include encrypted values
        for cred_data in data:
            cred = self._credentials[cred_data["cred_id"]]
            cred_data["value_encrypted"] = cred.value_encrypted

        # Encrypt with provided password
        if CRYPTO_AVAILABLE:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_AES_ITERATIONS)
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            fernet = Fernet(key)
            encrypted = fernet.encrypt(json.dumps(data).encode())
            Path(filepath).write_bytes(salt + encrypted)
        else:
            raise RuntimeError("cryptography package required for export")

    def import_encrypted(self, filepath: str, password: str) -> int:
        """Import encrypted backup"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package required")

        data = Path(filepath).read_bytes()
        salt = data[:16]
        encrypted = data[16:]

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_AES_ITERATIONS)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        imported = json.loads(decrypted)

        count = 0
        for cred_data in imported:
            cred = Credential(
                cred_id=cred_data["cred_id"],
                name=cred_data["name"],
                cred_type=cred_data["cred_type"],
                environment=cred_data["environment"],
                value_encrypted=cred_data["value_encrypted"],
                created_at=datetime.fromisoformat(cred_data["created_at"]),
            )
            self._credentials[cred.cred_id] = cred
            count += 1

        self._save()
        return count

    def get_statistics(self) -> dict[str, Any]:
        """Get credential statistics"""
        by_type: dict[str, int] = {}
        by_env: dict[str, int] = {}

        for cred in self._credentials.values():
            by_type[cred.cred_type] = by_type.get(cred.cred_type, 0) + 1
            by_env[cred.environment] = by_env.get(cred.environment, 0) + 1

        expiring_7d = len(self.check_expiring(7))
        expiring_30d = len(self.check_expiring(30))

        return {
            "total_credentials": len(self._credentials),
            "by_type": by_type,
            "by_environment": by_env,
            "expiring_7d": expiring_7d,
            "expiring_30d": expiring_30d,
            "encrypted": CRYPTO_AVAILABLE,
        }


_creds_instance: CredentialStore | None = None
_creds_lock = threading.Lock()

def get_creds() -> CredentialStore:
    global _creds_instance
    if _creds_instance is None:
        with _creds_lock:
            if _creds_instance is None:
                _creds_instance = CredentialStore()
    return _creds_instance


def get_credential(name: str, environment: str | None = None) -> str | None:
    """Convenience function"""
    return get_creds().get_by_name(name, environment)


def store_credential(name: str, value: str, cred_type: str = "api_key") -> Credential:
    """Convenience function"""
    return get_creds().store(name, value, cred_type)

__all__ = [
    "HAS_AESGCM",
    "CredentialType",
    "Environment",
    "Credential",
    "CredentialStore",
    "get_creds",
    "get_credential",
    "store_credential",
]
