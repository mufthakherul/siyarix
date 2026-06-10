# SPDX-License-Identifier: AGPL-3.0-or-later

"""Advanced Credential Vault with device + environment binding.

Provides hardware-bound, environment-tied encrypted credential storage.
Decryption requires BOTH the original device fingerprint AND the siyarix
runtime environment — even with the vault file and passphrase, decryption
is impossible from a different machine or outside the siyarix ecosystem.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Crypto (optional, fail fast) ──────────────────────────────────────────

HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _PBKDF2

    HAS_CRYPTO = True
except ImportError:
    pass

# ── Constants ─────────────────────────────────────────────────────────────

_VAULT_VERSION = 2
_KEY_SIZE = 32          # AES-256
_NONCE_SIZE = 12         # GCM nonce
_PBKDF2_ITERATIONS = 600_000
_CEREMONY_SALT = b"siyarix::vault::ceremony::a7f3c9e2b1d4"

# ── Errors ────────────────────────────────────────────────────────────────


class VaultError(Exception):
    """Base vault error."""


class VaultLockedError(VaultError):
    """Vault is sealed/locked."""


class VaultDeviceMismatchError(VaultError):
    """Vault was created on a different device."""


class VaultEnvironmentMismatchError(VaultError):
    """Vault was created in a different siyarix environment."""


class VaultTamperError(VaultError):
    """Vault integrity check failed — possible tampering."""


class VaultCorruptError(VaultError):
    """Vault file is corrupt or unreadable."""


# ── Data structures ───────────────────────────────────────────────────────


@dataclass
class VaultEntry:
    provider: str
    key_name: str
    value_encrypted: str
    created_at: str
    last_used: str = ""
    usage_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "key_name": self.key_name,
            "value_encrypted": self.value_encrypted,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "usage_count": self.usage_count,
        }


@dataclass
class VaultStatus:
    sealed: bool = True
    device_bound: bool = False
    environment_bound: bool = False
    device_match: bool | None = None
    env_match: bool | None = None
    tampered: bool | None = None
    credential_count: int = 0
    created_at: str = ""
    version: int = _VAULT_VERSION


# ── Fingerprint helpers ───────────────────────────────────────────────────


def _get_mac_addresses() -> list[str]:
    """Collect MAC addresses for device fingerprinting."""
    addrs: list[str] = []
    try:
        mac = uuid.getnode()
        if mac and mac != uuid.getnode().__class__:
            addrs.append(f"{mac:012x}")
    except Exception:
        pass
    try:
        import psutil
        for name, info in psutil.net_if_addrs().items():
            for addr in info:
                if addr.family == -1:
                    addrs.append(addr.address.replace(":", "").replace("-", "").lower())
    except Exception:
        pass
    return addrs


def _get_machine_id() -> str:
    """Get a stable machine identifier."""
    mid = ""
    # Linux: /etc/machine-id or /var/lib/dbus/machine-id
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            return Path(p).read_text().strip()
        except Exception:
            pass
    # macOS: IOPlatformUUID
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[3]
        except Exception:
            pass
    # Windows: wmic csproduct get uuid
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and "-" in line:
                    return line
        except Exception:
            pass
    return mid or platform.machine() + ":" + os.name


def _get_disk_serial() -> str:
    """Get disk serial number for device binding."""
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["wmic", "diskdrive", "get", "serialnumber"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("SerialNumber"):
                    return line
        except Exception:
            pass
    elif sys.platform == "linux":
        for disk in ("sda", "nvme0", "vda", "mmcblk0"):
            try:
                serial = Path(f"/sys/block/{disk}/serial").read_text().strip()
                if serial:
                    return serial
            except Exception:
                pass
    elif sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["diskutil", "info", "/"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "Serial Number" in line or "Device UUID" in line:
                    return line.split(":")[-1].strip()
        except Exception:
            pass
    return ""


def _get_tpm_ek_pub() -> str:
    """Get TPM endorsement key hash if available."""
    for tool in ("tpm2_getekcertificate", "tpm2_createek"):
        try:
            result = subprocess.run(
                [tool, "-c", "-o", "/dev/null"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return hashlib.sha256(result.stderr + result.stdout).hexdigest()[:16]
        except Exception:
            pass
    # Windows TPM via PowerShell
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-WmiObject -Namespace Root/CIMv2/Security/MicrosoftTpm "
                 "-Class Win32_Tpm | Select-Object -ExpandProperty "
                 "ManufacturerIdTxt"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return hashlib.sha256(result.stdout.encode()).hexdigest()[:16]
        except Exception:
            pass
    return ""


def compute_device_fingerprint() -> str:
    """Compute a hardware-bound device fingerprint."""
    parts = [
        platform.machine(),
        platform.processor() or platform.machine(),
        os.name,
        sys.platform,
        socket.gethostname(),
        str(uuid.getnode()),
        _get_machine_id(),
        _get_disk_serial(),
        _get_tpm_ek_pub(),
    ]
    parts.extend(_get_mac_addresses())
    raw = ":".join(p.replace(":", "").lower() for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()


def compute_environment_fingerprint() -> str:
    """Compute a siyarix runtime environment fingerprint."""
    siyarix_root = Path(__file__).resolve().parent
    parts = [
        str(siyarix_root),
        str(siyarix_root.parent),
        hashlib.sha256((siyarix_root / "__init__.py").read_bytes()).hexdigest()[:32]
        if (siyarix_root / "__init__.py").exists()
        else "",
        hashlib.sha256((siyarix_root / "credential_vault.py").read_bytes()).hexdigest()[:32],
        platform.python_implementation(),
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        _CEREMONY_SALT.hex(),
    ]
    # Include installed package version if available
    try:
        import importlib.metadata
        ver = importlib.metadata.version("siyarix")
        parts.append(ver)
    except Exception:
        pass
    raw = "||".join(p for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()


# ── Main vault ────────────────────────────────────────────────────────────


class CredentialVault:
    """Hardened, device-bound, environment-bound credential vault.

    Security properties:
    - AES-256-GCM encryption with PBKDF2 key derivation (600K iterations)
    - Device binding: vault is tied to hardware fingerprint (MAC, disk serial,
      TPM, machine ID). Decryption fails on any other device.
    - Environment binding: vault is tied to the siyarix installation itself.
      Decryption fails if the siyarix package is modified or moved.
    - HMAC integrity check detects any tampering with the vault file.
    - Optional user passphrase adds an additional factor.
    - Even with vault file + passphrase + key material, decryption is
      impossible without the original device AND siyarix environment.
    """

    def __init__(
        self,
        vault_path: str | Path | None = None,
        passphrase: str | None = None,
        skip_unseal: bool = False,
    ) -> None:
        if not HAS_CRYPTO:
            raise RuntimeError(
                "cryptography package required. Install: pip install cryptography"
            )

        self._config_dir = Path(
            os.getenv("SIYARIX_CONFIG_DIR", str(Path.home() / ".siyarix"))
        )
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._vault_path = Path(vault_path or self._config_dir / "vault.encrypted")
        self._passphrase = passphrase or os.getenv("SIYARIX_VAULT_PASSPHRASE") or ""

        # Runtime state
        self._entries: dict[str, VaultEntry] = {}
        self._unsealed = False
        self._device_fp = compute_device_fingerprint()
        self._env_fp = compute_environment_fingerprint()
        self._status = VaultStatus()

        if not skip_unseal and self._vault_path.exists():
            self._unseal()

    # ── Public API ───────────────────────────────────────────────────────

    def is_sealed(self) -> bool:
        return not self._unsealed

    @property
    def status(self) -> VaultStatus:
        return self._status

    def get(self, provider: str, key_name: str = "api_key") -> str | None:
        if not self._unsealed:
            raise VaultLockedError("Vault is sealed. Unseal first.")
        entry_id = f"{provider}:{key_name}"
        entry = self._entries.get(entry_id)
        if not entry:
            return None
        try:
            value = self._decrypt_value(entry.value_encrypted)
            entry.usage_count += 1
            entry.last_used = datetime.utcnow().isoformat()
            self._save()
            return value
        except Exception as exc:
            logger.error("Failed to decrypt entry %s: %s", entry_id, exc)
            return None

    def set(
        self,
        provider: str,
        value: str,
        key_name: str = "api_key",
    ) -> None:
        if not self._unsealed:
            raise VaultLockedError("Vault is sealed. Unseal first.")
        entry_id = f"{provider}:{key_name}"
        encrypted = self._encrypt_value(value)
        now = datetime.utcnow().isoformat()
        if entry_id in self._entries:
            self._entries[entry_id].value_encrypted = encrypted
            self._entries[entry_id].last_used = now
        else:
            self._entries[entry_id] = VaultEntry(
                provider=provider,
                key_name=key_name,
                value_encrypted=encrypted,
                created_at=now,
                last_used=now,
            )
        self._save()

    def delete(self, provider: str, key_name: str = "api_key") -> bool:
        entry_id = f"{provider}:{key_name}"
        if entry_id in self._entries:
            del self._entries[entry_id]
            self._save()
            return True
        return False

    def list_keys(self) -> list[dict[str, Any]]:
        if not self._unsealed:
            raise VaultLockedError("Vault is sealed.")
        return [
            {
                "provider": e.provider,
                "key_name": e.key_name,
                "created_at": e.created_at,
                "last_used": e.last_used,
                "usage_count": e.usage_count,
            }
            for e in self._entries.values()
        ]

    def rekey(self, new_passphrase: str | None = None) -> None:
        """Re-encrypt all entries with a new derived key (key rotation)."""
        if not self._unsealed:
            raise VaultLockedError("Vault is sealed.")
        if new_passphrase is not None:
            self._passphrase = new_passphrase
        # Re-encrypt every entry in-place
        for entry_id, entry in list(self._entries.items()):
            try:
                plain = self._decrypt_value(entry.value_encrypted)
                entry.value_encrypted = self._encrypt_value(plain)
            except Exception as exc:
                logger.warning("Failed to rekey entry %s: %s", entry_id, exc)
        self._save()

    def seal(self) -> None:
        """Seal the vault (clear decryption key from memory)."""
        self._unsealed = False
        self._status.sealed = True
        self._entries.clear()

    def destroy(self) -> None:
        """Delete the vault file permanently."""
        self.seal()
        if self._vault_path.exists():
            self._vault_path.unlink()

    # ── Internal: key derivation ─────────────────────────────────────────

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive AES-256 key from device FP + environment FP + passphrase."""
        material = f"{self._device_fp}:::{self._env_fp}:::{self._passphrase}"
        kdf = _PBKDF2(
            algorithm=_hashes.SHA256(),
            length=_KEY_SIZE,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return kdf.derive(material.encode())

    def _derive_key_no_passphrase(self, salt: bytes) -> bytes:
        """Same but without the user passphrase (for HMAC integrity)."""
        material = f"{self._device_fp}:::{self._env_fp}:::"
        kdf = _PBKDF2(
            algorithm=_hashes.SHA256(),
            length=_KEY_SIZE,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return kdf.derive(material.encode())

    # ── Internal: encryption ─────────────────────────────────────────────

    def _encrypt_value(self, plaintext: str) -> str:
        nonce = os.urandom(_NONCE_SIZE)
        # Derive a per-value key from the master
        salt = os.urandom(16)
        key = self._derive_key(salt)
        ct = _AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(salt + nonce + ct).decode()

    def _decrypt_value(self, encrypted: str) -> str:
        raw = base64.b64decode(encrypted)
        salt = raw[:16]
        nonce = raw[16:28]
        ct = raw[28:]
        key = self._derive_key(salt)
        return _AESGCM(key).decrypt(nonce, ct, None).decode()

    # ── Internal: vault load/save ─────────────────────────────────────────

    def _unseal(self) -> None:
        """Read and decrypt the vault file. Raises if device/environment mismatch."""
        if not self._vault_path.exists():
            return

        try:
            raw = self._vault_path.read_bytes()
        except Exception as exc:
            raise VaultCorruptError(f"Cannot read vault file: {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise VaultCorruptError(f"Vault file is not valid JSON: {exc}") from exc

        version = data.get("version", 1)
        if version > _VAULT_VERSION:
            raise VaultCorruptError(
                f"Vault version {version} is newer than supported {_VAULT_VERSION}"
            )

        vault_salt = base64.b64decode(data["salt"])

        # ── Device binding check ──────────────────────────────────────────
        stored_device_hash = data.get("device_fp_hash", "")
        current_device_hash = hashlib.sha256(self._device_fp.encode()).hexdigest()
        matches_device = stored_device_hash == current_device_hash
        self._status.device_match = matches_device
        self._status.device_bound = bool(stored_device_hash)

        if not matches_device and stored_device_hash:
            raise VaultDeviceMismatchError(
                "Vault is bound to a different device. "
                "Decryption requires the original device where this vault was created."
            )

        # ── Environment binding check ─────────────────────────────────────
        stored_env_hash = data.get("env_fp_hash", "")
        current_env_hash = hashlib.sha256(self._env_fp.encode()).hexdigest()
        matches_env = stored_env_hash == current_env_hash
        self._status.env_match = matches_env
        self._status.environment_bound = bool(stored_env_hash)

        if not matches_env and stored_env_hash:
            raise VaultEnvironmentMismatchError(
                "Vault is bound to a different siyarix environment. "
                "Decryption requires the original siyarix installation "
                "where this vault was created."
            )

        # ── HMAC integrity check ──────────────────────────────────────────
        stored_hmac = data.get("hmac", "")
        payload_for_hmac = json.dumps(
            {
                "version": data["version"],
                "salt": data["salt"],
                "device_fp_hash": data["device_fp_hash"],
                "env_fp_hash": data["env_fp_hash"],
                "created_at": data["created_at"],
                "credentials": data["credentials"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        integrity_key = self._derive_key_no_passphrase(vault_salt)
        expected_hmac = _hmac.new(
            integrity_key, payload_for_hmac.encode(), hashlib.sha256
        ).hexdigest()
        matches_hmac = _hmac.compare_digest(stored_hmac, expected_hmac)
        self._status.tampered = not matches_hmac

        if not matches_hmac:
            raise VaultTamperError(
                "Vault integrity check failed — file has been tampered with."
            )

        # ── Decrypt credentials ──────────────────────────────────────────
        try:
            cred_salt = base64.b64decode(data["credentials"]["salt"])
            cred_nonce = base64.b64decode(data["credentials"]["nonce"])
            cred_ct = base64.b64decode(data["credentials"]["ciphertext"])
            cred_key = self._derive_key(cred_salt)
            decrypted = _AESGCM(cred_key).decrypt(cred_nonce, cred_ct, None).decode()
            entries_data = json.loads(decrypted)
        except Exception as exc:
            raise VaultCorruptError(f"Failed to decrypt vault credentials: {exc}") from exc

        for ed in entries_data:
            eid = f"{ed['provider']}:{ed['key_name']}"
            self._entries[eid] = VaultEntry(
                provider=ed["provider"],
                key_name=ed["key_name"],
                value_encrypted=ed["value_encrypted"],
                created_at=ed.get("created_at", ""),
                last_used=ed.get("last_used", ""),
                usage_count=ed.get("usage_count", 0),
            )

        self._unsealed = True
        self._status.sealed = False
        self._status.credential_count = len(self._entries)
        self._status.created_at = data.get("created_at", "")
        self._status.version = version

    def _save(self) -> None:
        """Encrypt and write the vault file."""
        # ── Serialise entries ─────────────────────────────────────────────
        entries_data = [e.to_dict() for e in self._entries.values()]

        # ── Encrypt credentials ───────────────────────────────────────────
        cred_salt = os.urandom(16)
        cred_nonce = os.urandom(_NONCE_SIZE)
        cred_key = self._derive_key(cred_salt)
        cred_ct = _AESGCM(cred_key).encrypt(
            cred_nonce, json.dumps(entries_data, separators=(",", ":")).encode(), None
        )
        credentials_blob = {
            "salt": base64.b64encode(cred_salt).decode(),
            "nonce": base64.b64encode(cred_nonce).decode(),
            "ciphertext": base64.b64encode(cred_ct).decode(),
        }

        # ── Vault header ──────────────────────────────────────────────────
        vault_salt = os.urandom(32)
        now = datetime.utcnow().isoformat()
        device_hash = hashlib.sha256(self._device_fp.encode()).hexdigest()
        env_hash = hashlib.sha256(self._env_fp.encode()).hexdigest()

        payload_for_hmac = json.dumps(
            {
                "version": _VAULT_VERSION,
                "salt": base64.b64encode(vault_salt).decode(),
                "device_fp_hash": device_hash,
                "env_fp_hash": env_hash,
                "created_at": now,
                "credentials": credentials_blob,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        integrity_key = self._derive_key_no_passphrase(vault_salt)
        vault_hmac = _hmac.new(
            integrity_key, payload_for_hmac.encode(), hashlib.sha256
        ).hexdigest()

        vault_data = json.loads(payload_for_hmac)
        vault_data["hmac"] = vault_hmac

        self._vault_path.write_text(json.dumps(vault_data, indent=2))
        # Protect vault file on POSIX
        try:
            if os.name != "nt":
                os.chmod(self._vault_path, 0o600)
        except Exception:
            pass

    # ── Factory: create a new vault ──────────────────────────────────────

    @classmethod
    def create(
        cls,
        vault_path: str | Path | None = None,
        passphrase: str | None = None,
        skip_if_exists: bool = True,
    ) -> CredentialVault:
        """Create a new vault with the current device + environment binding.

        This is the 'key ceremony' — after creation, the vault is permanently
        bound to this machine and siyarix installation.
        """
        config_dir = Path(
            os.getenv("SIYARIX_CONFIG_DIR", str(Path.home() / ".siyarix"))
        )
        config_dir.mkdir(parents=True, exist_ok=True)
        vp = Path(vault_path or config_dir / "vault.encrypted")

        if skip_if_exists and vp.exists():
            logger.info("Vault already exists at %s — loading.", vp)
            return cls(vault_path=vp, passphrase=passphrase)

        logger.info(
            "Creating new credential vault bound to this device and environment."
        )
        vault = cls(vault_path=vp, passphrase=passphrase, skip_unseal=True)
        vault._unsealed = True
        vault._save()
        vault._status.sealed = False
        vault._status.device_bound = True
        vault._status.environment_bound = True
        return vault


# ── Singleton accessor ────────────────────────────────────────────────────

_vault_instance: CredentialVault | None = None


def get_vault(
    passphrase: str | None = None,
    create: bool = True,
) -> CredentialVault:
    """Get the global vault instance (singleton)."""
    global _vault_instance
    if _vault_instance is None:
        try:
            _vault_instance = CredentialVault(passphrase=passphrase)
        except (VaultDeviceMismatchError, VaultEnvironmentMismatchError, VaultTamperError):
            logger.error("Vault cannot be opened on this device/environment.")
            raise
        except VaultCorruptError:
            if create:
                _vault_instance = CredentialVault.create(passphrase=passphrase)
            else:
                raise
        except FileNotFoundError:
            if create:
                _vault_instance = CredentialVault.create(passphrase=passphrase)
            else:
                raise
    return _vault_instance


def vault_get(provider: str, key_name: str = "api_key") -> str | None:
    """Convenience: get a credential from the global vault."""
    try:
        return get_vault().get(provider, key_name)
    except Exception as exc:
        logger.debug("vault_get(%s) failed: %s", provider, exc)
        return None


def vault_set(provider: str, value: str, key_name: str = "api_key") -> None:
    """Convenience: store a credential in the global vault."""
    get_vault().set(provider, value, key_name)


def vault_delete(provider: str, key_name: str = "api_key") -> bool:
    """Convenience: delete a credential from the global vault."""
    return get_vault().delete(provider, key_name)


__all__ = [
    "CredentialVault",
    "VaultError",
    "VaultLockedError",
    "VaultDeviceMismatchError",
    "VaultEnvironmentMismatchError",
    "VaultTamperError",
    "VaultCorruptError",
    "VaultStatus",
    "get_vault",
    "vault_get",
    "vault_set",
    "vault_delete",
    "compute_device_fingerprint",
    "compute_environment_fingerprint",
]
