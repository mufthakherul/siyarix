# 🔐 Hardware Security Module (HSM) Integration

As Siyarix grows, I'm working on adding support for hardware-backed security. While HSM integration is currently **under active development**, this document outlines the plan for secure key storage.

!!! note
    **Developer Status:** Basic HSM detection currently exists as a stub in `chat/stubs.py` (look for `HSMService`), but the full integration is a work in progress.

## 📊 Current Integration Status

I'm aiming to support some common hardware standards eventually:

| Hardware Type | Target Library | Current Status |
|---------------|----------------|----------------|
| **YubiKey** | `ykman` | 🚧 Under development |
| **PKCS#11 Devices** | `python-pkcs11` | 🚧 Under development |
| **Software Fallback** | Built-in | ✅ Fully Implemented (`CredentialStore`) |

## 🚀 Planned Capabilities

Once released, Siyarix's HSM integration should allow you to:
- **Secure Key Storage:** Lock `CredentialStore` master encryption keys inside hardware.
- **Hardware Cryptography:** Offload sensitive signing operations.

## 🛠️ Current Workaround: AWS KMS

If you need a workaround today, the `CredentialStore` natively supports **AWS KMS envelope encryption**.

```bash
# Enable the KMS provider
export SIYARIX_KMS_PROVIDER=aws

# Point it to your specific key
export AWS_KMS_KEY_ID=your-aws-kms-key-id
```

!!! tip
    This keeps your local credentials encrypted with a data key from AWS KMS!

## 📂 Cross-Platform PKCS#11 Paths (Reference)

For anyone who wants to help contribute to the PKCS#11 integration, here are default driver paths:

| OS Platform | Default Driver Path |
|-------------|---------------------|
| **Windows** | `C:\Windows\System32\opensc-pkcs11.dll` |
| **macOS** | `/usr/local/lib/opensc-pkcs11.so` |
| **Linux** | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
