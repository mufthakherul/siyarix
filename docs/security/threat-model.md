# Threat Model

This document outlines the security threat model for Siyarix, identifying assets, trust boundaries, potential threats, and mitigations.

## Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| AI provider API keys | Keys for OpenAI, Gemini, Anthropic, etc. | CRITICAL |
| Scan results | Target data, open ports, vulnerabilities | HIGH |
| Knowledge graph | Mapped relationships (hosts, credentials) | HIGH |
| Session logs | Command history, tool outputs | HIGH |
| Config file | Provider settings, proxy settings | MEDIUM |
| Credential store | Encrypted vault of stored credentials | CRITICAL |

## Trust boundaries

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   User TTY   │────▶│  Siyarix    │────▶│  AI Provider │
│  (terminal)  │     │  CLI Process│     │  (cloud)     │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
                    ┌───────▼───────┐
                    │  External     │
                    │  Tools       │
                    │  (nmap, etc.)│
                    └───────────────┘
```

### Boundary 1: User → Siyarix

- **Threat**: Malicious input (shell injection, command injection)
- **Mitigation**: Syntax validation, length limits, character restrictions

### Boundary 2: Siyarix → AI Provider

- **Threat**: Sensitive data sent to third-party API
- **Mitigation**: Masking engine redacts credentials, IPs, hostnames

### Boundary 3: Siyarix → External Tools

- **Threat**: Tool vulnerability or unexpected behavior
- **Mitigation**: Subprocess isolation, timeouts, output size limits

## Threats and mitigations

### T1: API key exfiltration

| Attribute | Detail |
|-----------|--------|
| **Threat** | API keys sent to AI provider or logged |
| **Impact** | CRITICAL — unauthorized AI usage, cost |
| **Mitigation** | Masking engine redacts keys before sending to providers. Credential store encrypts at rest. Keys never logged. |

### T2: Prompt injection

| Attribute | Detail |
|-----------|--------|
| **Threat** | Malicious input causes AI to generate dangerous commands |
| **Impact** | HIGH — unauthorized command execution |
| **Mitigation** | Permission gate validates all commands before execution. Danger analysis blocks 38 patterns. Response sensor validates AI output. |

### T3: Data leakage to AI provider

| Attribute | Detail |
|-----------|--------|
| **Threat** | Internal hostnames, credentials, or sensitive data sent to third-party AI |
| **Impact** | HIGH — data exposure |
| **Mitigation** | Bidirectional masking replaces IPs and hostnames. Credentials are fully redacted. Session-scoped masking ensures consistency. |

### T4: Unauthorized tool execution

| Attribute | Detail |
|-----------|--------|
| **Threat** | AI or user executes destructive system commands |
| **Impact** | CRITICAL — system damage |
| **Mitigation** | Three-stage permission gate. 38 dangerous pattern checks. Persona-based ACLs. Safe mode blocks all exploitation. |

### T5: Audit log tampering

| Attribute | Detail |
|-----------|--------|
| **Threat** | Attacker modifies audit log to hide actions |
| **Impact** | HIGH — loss of accountability |
| **Mitigation** | SHA-256 hash chain links entries. Any modification breaks the chain. SIEM forwarding provides off-system copy. |

### T6: Credential store compromise

| Attribute | Detail |
|-----------|--------|
| **Threat** | Encrypted vault keys or contents stolen |
| **Impact** | CRITICAL — all stored credentials exposed |
| **Mitigation** | AES-256-GCM encryption. Keys stored in OS keyring. Optional KMS envelope encryption. Key rotation support. |

### T7: AI provider compromise

| Attribute | Detail |
|-----------|--------|
| **Threat** | AI provider returns malicious output or is compromised |
| **Impact** | HIGH — command injection, data exfiltration |
| **Mitigation** | Permission gate blocks malformed commands. Noop provider as always-available fallback. |

## Security assumptions

- The user's terminal environment is trusted
- The host OS file permissions protect `~/.siyarix/`
- AI providers are untrusted third parties
- External tools are executed as subprocesses with standard OS isolation
- Network traffic to AI providers uses TLS
