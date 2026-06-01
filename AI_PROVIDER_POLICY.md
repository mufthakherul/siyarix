# AI Provider Policy

**Version:** 1.0.0
**Effective Date:** May 2026

This document defines the architecture, governance, and operational rules for AI provider integration in the Siyarix platform. It applies to all components that interact with AI models, whether cloud-hosted or local.

---

## 1. Provider Abstraction Layer

Siyarix implements a **provider-agnostic abstraction layer** (`src/siyarix/providers.py`) that decouples the execution engine from any specific AI model or vendor.

### 1.1 Architecture

```
Execution Engine
       │
       ▼
Provider Interface (plan / chat / validate / close)
       │
       ├── Google Gemini (via google-generativeai SDK)
       ├── OpenAI (via openai SDK)
       ├── Anthropic (via anthropic SDK)
       ├── Ollama (local — REST API)
       ├── LM Studio (local — OpenAI-compatible API)
       ├── Groq (cloud — OpenAI-compatible API)
       ├── Together (cloud — OpenAI-compatible API)
       ├── Custom Endpoint (any OpenAI-compatible API)
       └── NoopProvider (offline / testing — no external call)
```

### 1.2 Interface Contract

Every registered provider must implement:

| Method | Purpose |
|--------|---------|
| `plan(prompt, context)` | Generate an execution plan from natural language |
| `chat(history)` | Multi-turn conversation |
| `validate()` | Check credentials and endpoint availability |
| `close()` | Clean up resources |

No single provider is required. The system operates with whatever provider is configured and available.

---

## 2. Provider Registration

Providers are registered in the central `ProviderRegistry` during startup:

```python
from siyarix.providers import registry
registry.register("gemini", GeminiAdapter)
registry.register("openai", OpenAIAdapter)
# ... etc.
```

The registry maintains an ordered preference list. The active provider is selected at runtime based on configuration.

---

## 3. Dynamic Provider Selection

### 3.1 Selection Criteria

The active provider is determined by:

1. **User configuration** — explicit `/model <provider>` setting
2. **Availability** — provider must pass `validate()` check
3. **Task type** — certain providers may be preferred for specific task categories
4. **Cost constraints** — users may configure cost-based routing preferences
5. **Fallback chain** — if primary provider fails, secondary providers are tried

### 3.2 Configuration

```bash
# Interactive session
siyarix> /model gemini

# Environment variable
export SIYARIX_PROVIDER=openai

# Preferences file (~/.siyarix/config.yaml)
provider: gemini
provider_failover:
  - openai
  - ollama
```

### 3.3 Task-Based Routing (Future)

The system may route different task types to different providers:

| Task Type | Preferred Provider | Rationale |
|-----------|-------------------|-----------|
| General planning | Gemini / OpenAI | Strong JSON generation |
| Security analysis | Claude | Strong reasoning |
| Local/offline | Ollama / LM Studio | Data never leaves host |
| Low-cost bulk | Groq / Together | High throughput, low cost |

---

## 4. Failover Behavior

### 4.1 Automatic Failover

When the active provider fails (timeout, authentication error, rate limit):

1. The system logs the failure with provider name and error details.
2. If a failover chain is configured, the next provider in the chain is activated.
3. The user is notified of the provider switch.
4. The original request is retried on the fallback provider.

### 4.2 Manual Override

Users can force a provider switch at any time:

```text
/model openai
```

### 4.3 Fallback to Offline Mode

If no AI provider is available:

- Siyarix falls back to **local heuristic planning** (no LLM required)
- Tool execution continues without AI assistance
- Users receive a clear notification that AI features are unavailable

---

## 5. Security Boundaries per Provider

### 5.1 Data Masking

Before any data is sent to a cloud AI provider, the **bidirectional masking engine** (`masking.py`) is applied:

| Data Type | Masking Action |
|-----------|----------------|
| IP addresses | Replaced with `10.x.x.x` placeholders |
| Domain names | Replaced with `example.com` placeholders |
| API keys / tokens | Replaced with `[REDACTED]` |
| Credentials | Replaced with `[REDACTED]` |
| Custom patterns | User-defined regex replacement |

The masking engine is **always active** for cloud providers and can be configured for local providers.

### 5.2 Local Model Recommendation

For operations involving:
- Classified or sensitive targets
- Air-gapped environments
- GDPR/CCPA-sensitive data processing
- Internal corporate networks without data export authorization

**Local models (Ollama, LM Studio) are strongly recommended** over cloud providers.

### 5.3 Provider-Specific Security Notes

| Provider | Security Consideration |
|----------|------------------------|
| Google Gemini | Data processed on Google Cloud; subject to Google AI Privacy Policy |
| OpenAI | Data processed on Azure/AWS; subject to OpenAI API Data Usage Policy |
| Anthropic | Data processed on Anthropic infrastructure; subject to Anthropic Privacy Policy |
| Groq | Data processed on GroqCloud; review Groq Privacy Policy |
| Together | Data processed on Together infrastructure; review Together Privacy Policy |
| Ollama | Fully local; no data leaves host |
| LM Studio | Fully local; no data leaves host |

---

## 6. API Key Handling

### 6.1 Storage

- All API keys are stored in the **encrypted credential vault** (`credential_store.py`).
- Encryption uses **AES-256-GCM** with a locally derived master key.
- Keys are never stored in source code, configuration files committed to version control, or log output.
- The `.env` file (used for runtime convenience) is listed in `.gitignore`.

### 6.2 Provisioning

```text
siyarix> /key set gemini <your-api-key>
siyarix> /key set openai <your-api-key>
```

Keys are encrypted immediately upon entry and never appear in shell history.

### 6.3 Rotation

```text
siyarix> /key rotate
```

Key rotation re-encrypts all stored credentials with a new master key.

### 6.4 Clearance

Keys are decrypted only at runtime and held in memory for the duration of a single request. They are not persisted in decrypted form.

---

## 7. No Hard Dependency on Any Single Provider

- **No provider SDK is a hard runtime dependency.** Optional provider SDKs (`openai`, `anthropic`, `google-generativeai`) are installed only when the user chooses the relevant extras:

  ```bash
  pip install siyarix           # core only (no AI providers)
  pip install "siyarix[all]"    # includes popular providers
  ```

- **The system starts and operates without any AI provider.** Core functionality (tool registry, execution engine, CLI) is fully functional offline.
- **Heuristic planning** provides basic plan generation without any LLM.
- **Provider adapters** are loaded lazily — unused providers do not consume resources.

---

## 8. Logging and Audit Expectations

### 8.1 Provider Interaction Logging

All provider interactions are logged with:

- Provider name and model used
- Request timestamp and duration
- Success / failure status
- Error type (if applicable)
- Plan summary (not full prompts, to avoid logging sensitive data)

### 8.2 Audit Trail

- Provider selections and switches are recorded in the session audit log.
- Failover events are logged with cause and resolution.
- API key operations (set, rotate, delete) are logged with timestamp.

### 8.3 No Prompt Storage

By default, full AI prompts are not stored in logs. Debug logging (`SIYARIX_LOG_LEVEL=DEBUG`) may capture prompts for troubleshooting; users are advised to enable debug logging only in controlled environments.

---

## 9. Prohibited Provider Use

Providers must not be used to:

- Generate malicious code or payloads
- Automate unauthorized access
- Process unauthorized personal data
- Bypass safety mechanisms intentionally
- Engage in activities prohibited by the [Ethical Use Policy](ETHICAL_USE.md) or [Responsible AI Use Policy](RESPONSIBLE_AI_USE.md)

---

## 10. Compliance

Organizations deploying Siyarix should review:

- **EU AI Act**: Risk classification of AI-assisted security operations
- **Data Protection**: GDPR/CCPA implications of sending data to cloud AI providers
- **Sector Regulations**: PCI-DSS, HIPAA, or other sector-specific rules on AI data processing
- **Export Control**: AI model access may be subject to export restrictions

---

*This policy supplements the GNU Affero General Public License v3.0 or later. It does not create binding legal obligations beyond applicable law. Consult qualified professionals for regulatory compliance.*

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
