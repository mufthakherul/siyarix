# HSM Integration

Siyarix supports Hardware Security Modules (HSMs) for secure key storage and cryptographic operations. **Note**: This feature is a stub implementation — basic HSM detection exists but full integration is not yet complete.

## Supported HSM types

| Type | Library | Status |
|------|---------|--------|
| YubiKey | `ykman` | Stub |
| PKCS#11 | `python-pkcs11` | Stub |
| TPM | (placeholder) | Stub |
| Software fallback | Built-in | Implemented |

## Usage

```bash
siyarix health
# Shows: HSM: connected (YubiKey 5 NFC) — if detected
```

## HSM service (`hsm_manager.py`)

The `HSMService` provides a unified interface (stub implementation):

```python
from siyarix.hsm_manager import HSMService

hsm = HSMService()
status = hsm.connect()
if status.connected:
    hsm.store_secret("my_key", "my_secret_value")
```

## Cross-platform PKCS#11 paths

| Platform | Default path |
|----------|-------------|
| Windows | `C:\Windows\System32\opensc-pkcs11.dll` |
| macOS | `/usr/local/lib/opensc-pkcs11.so` |
| Linux | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |

## Key operations

| Operation | Description |
|-----------|-------------|
| `connect()` | Initialize HSM connection |
| `disconnect()` | Close HSM connection securely |
| `store_secret()` | Store a secret in HSM-backed storage |
| `get_status()` | Get HSM connection and device status |
| `list_keys()` | List available keys on the HSM |

## Status data class

```python
@dataclass
class HSMStatus:
    connected: bool
    provider: str        # "yubikey", "pkcs11", "tpm", "software"
    model: str           # Device model
    serial: str          # Device serial number
    has_pin: bool        # Whether PIN is required
    algorithms: list     # Supported algorithms
    slots_available: int # Number of available key slots
```

## Use cases

- Enterprise deployments: Meet FIPS/HSM compliance requirements
- Key protection: Store API keys and signing keys in hardware
- Credential store backup: HSM as root of trust for credential encryption
- Code signing: Sign tool updates and reports with HSM-backed keys
