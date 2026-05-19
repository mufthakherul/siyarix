# Security & Secrets Model

NexSec implements a defense-in-depth approach to managing security tools, API keys, and audit logs.

## Enterprise Credential Vault

The `CredentialStore` (accessible via `nexsec auth`) is a secure vault for API keys (e.g., OpenAI, Gemini) and tool credentials.

- **Encryption**: All secrets are encrypted at rest using **Fernet symmetric encryption**.
- **Envelope Encryption (Optional)**: NexSec supports AWS KMS for envelope encryption. When enabled (`NEXSEC_KMS_PROVIDER=aws`), the local Fernet key is protected by an AWS KMS master key.
- **Environment Scoping**: Credentials can be scoped to specific environments (e.g., `dev`, `staging`, `prod`) to prevent accidental usage across contexts.
- **Key Management**:
    - The local master key is stored in `~/.nexsec/.vault_key` with `600` permissions.
    - Use `nexsec auth set-key <provider>` to safely store keys without them appearing in your shell history.

## High-Integrity Audit Trail

NexSec maintains a local enterprise audit trail (`~/.nexsec/audit.json`) that records every significant action taken by the agent.

- **Immutable Chain**: Each audit event contains a cryptographic hash of the previous event, creating a verifiable chain of integrity.
- **Verification**: Run `nexsec audit verify` to ensure the audit log has not been tampered with.
- **Compliance Export**: Supports SOC2, ISO 27001, and NIST report generation via `nexsec audit report`.

## Execution Safety

- **Safety Resolver**: The autonomous engine passes all generated commands through a safety resolver that checks for dangerous patterns (e.g., `rm -rf /`, `curl | sudo sh`) before execution.
- **Dry-Run Mode**: Always use `--dry-run` when testing new natural language prompts to see the proposed execution plan without running any commands.
- **CI/CD Policy Gates**: Use `nexsec ci gate` in your pipelines to automatically fail builds if critical vulnerabilities are detected or if the system health is compromised.

## Best Practices

1. **Rotate Keys**: Use `nexsec auth set-key` to rotate API keys periodically.
2. **Use Environments**: Configure different `NEXSEC_PROFILE` values for development and production to keep credentials isolated.
3. **Audit Monitoring**: Periodically verify your audit chain with `nexsec audit verify`.
4. **KMS in Production**: For production deployments, always configure a managed KMS provider (AWS KMS) to protect the credential vault.
