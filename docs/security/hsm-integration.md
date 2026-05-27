# HSM Integration

Siyarix supports Hardware Security Modules (HSMs) for secure key storage and cryptographic operations.

## Supported HSM types

| Type | Library | Use case |
|------|---------|----------|
| YubiKey | `ykman` | Hardware-backed authentication |
| PKCS#11 | `python-pkcs11` | Enterprise HSM devices |
| TPM | (placeholder) | Trusted Platform Module |
| Software fallback | Built-in | Development/testing |

## Usage

```bash
# Check HSM status
siyarix health
# Shows: HSM: connected (YubiKey 5 NFC)

# Store a secret in HSM
siyarix creds set --hsm api_key
```

## HSM service

The `HSMService` provides a unified interface:

```python
from siyarix.hsm_manager import HSMService

hsm = HSMService()
status = hsm.connect()
if status.connected:
    hsm.store_secret("my_key", "my_secret_value")
```

## Cross-platform PKCS#11

The HSM manager auto-discovers PKCS#11 libraries per platform:

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

## Status reporting

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

- **Enterprise deployments**: Meet FIPS/HSM compliance requirements
- **Key protection**: Store API keys and signing keys in hardware
- **Credential store backup**: HSM as root of trust for credential encryption
- **Code signing**: Sign tool updates and reports with HSM-backed keys
