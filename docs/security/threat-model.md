# Threat Model

This document identifies assets, trust boundaries, threats, and mitigations for Siyarix.

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
- **Impact**: CRITICAL — unauthorized AI usage, cost
- **Mitigation**: Masking engine redacts keys before sending. Credential store encrypts at rest. Keys never logged.

### T2: Prompt injection
- **Impact**: HIGH — unauthorized command execution
- **Mitigation**: Permission gate validates all commands before execution. Danger analysis blocks 38 patterns. Response sensor validates AI output.

### T3: Data leakage to AI provider
- **Impact**: HIGH — data exposure
- **Mitigation**: Bidirectional masking replaces IPs and hostnames. Credentials fully redacted. Session-scoped masking ensures consistency.

### T4: Unauthorized tool execution
- **Impact**: CRITICAL — system damage
- **Mitigation**: Two-stage permission gate. 38 dangerous pattern checks. Persona-based ACLs. Safe mode blocks all exploitation.

### T5: Audit log tampering
- **Impact**: HIGH — loss of accountability
- **Mitigation**: SHA-256 hash chain links entries. Any modification breaks the chain. SIEM forwarding provides off-system copy.

### T6: Credential store compromise
- **Impact**: CRITICAL — all stored credentials exposed
- **Mitigation**: AES-256-GCM encryption. Keys stored in OS keyring. Optional KMS envelope encryption. Key rotation support.

### T7: AI provider compromise
- **Impact**: HIGH — command injection, data exfiltration
- **Mitigation**: Permission gate blocks malformed commands. Registry fallback always available.

## Security assumptions

- The user's terminal environment is trusted
- Host OS file permissions protect `~/.siyarix/`
- AI providers are untrusted third parties
- External tools execute as subprocesses with standard OS isolation
- Network traffic to AI providers uses TLS
