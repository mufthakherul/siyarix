# AI Provider Policy

**Version:** 1.0.1
**Effective Date:** June 2026
**Applies to:** All AI provider integrations in Siyarix v1.0.1

This document defines the architecture, governance, security boundaries, and operational rules for AI provider integration in the Siyarix platform. It applies to all components that interact with AI models, whether cloud-hosted APIs or locally executed models.

---

## 1. Provider Abstraction Layer

Siyarix implements a **provider-agnostic abstraction layer** that decouples the execution engine from any specific AI model, vendor, or SDK. Providers are implemented as adapter classes registered in the central `ProviderRegistry`.

### 1.1 Architecture

```
Execution Engine
       |
       v
ProviderManager (singleton -- 24+ provider profiles)
       |
       +-- Cloud Providers
       |   +-- OpenAI (GPT-4o, GPT-4, GPT-3.5-turbo, o-series)
       |   +-- Google Gemini (Gemini 2.0 Flash, 1.5 Pro, 1.5 Flash)
       |   +-- Anthropic (Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku)
       |   +-- Groq (Llama 3, Mixtral, Gemma -- low-latency inference)
       |   +-- Together AI (Mixtral, Llama, DeepSeek, Qwen)
       |   +-- OpenRouter (multi-model router to 200+ models)
       |   +-- DeepSeek (DeepSeek-V2, DeepSeek-Coder)
       |   +-- xAI / Grok (Grok-1, Grok-2)
       |   +-- Mistral AI (Mistral Large, Mistral Small, Codestral)
       |   +-- Perplexity (Sonar, Sonar-Pro, Llama-3-Sonar)
       |   +-- Cerebras (ultra-fast inference on CS-3 systems)
       |   +-- Fireworks AI (open models, firefunction-v2)
       |   +-- Z.AI (Zhipu AI -- GLM-4 series)
       |   +-- MiniMax (MiniMax-Text-01)
       |   +-- Moonshot / Kimi (Moonshot-v1)
       |   +-- NVIDIA Nemotron (Nemotron-4, Llama-3.1-Nemotron)
       |   +-- Hugging Face (Inference API, Inference Endpoints)
       |   +-- Azure OpenAI (enterprise OpenAI with managed compliance)
       |   +-- OpenCode Zen (lightweight hosted inference)
       |
       +-- Local Providers (no data leaves host)
       |   +-- Ollama (REST API -- supports 100+ open models)
       |   +-- LM Studio (OpenAI-compatible local API)
       |   +-- llama.cpp (CPU-efficient inference via server binary)
       |   +-- vLLM (high-throughput GPU-accelerated serving)
       |   +-- LocalAI (drop-in OpenAI replacement, local)
       |
       +-- Offline / Fallback
           +-- Registry / Heuristic Planner (no LLM required)
```

### 1.2 Provider Interface Contract

Every registered provider adapter must implement the following interface:

| Method | Signature | Purpose |
|--------|-----------|---------|
| `plan()` | `plan(prompt: str, context: dict) -> ExecutionPlan` | Generate an execution plan from natural language |
| `chat()` | `chat(history: list[Message]) -> ChatResponse` | Multi-turn conversational interaction |
| `validate()` | `validate() -> ProviderStatus` | Check credentials, endpoint availability, model accessibility |
| `close()` | `close() -> None` | Clean up resources, close connections |

No single provider is required. The system operates with whichever providers are configured and available.

---

## 2. Provider Registration

Providers are registered in the central `ProviderRegistry` during platform startup. Registration is dynamic and lazy -- providers are only loaded when their adapter class is needed.

```python
from siyarix.providers import registry

registry.register("gemini", GeminiAdapter)
registry.register("openai", OpenAIAdapter)
registry.register("ollama", OllamaAdapter)
# ... additional providers
```

The registry maintains an ordered preference list. The active provider is selected at runtime based on user configuration, availability, and task type.

---

## 3. Provider Selection

### 3.1 Selection Criteria

The active provider is determined by the following criteria, evaluated in order:

1. **User configuration** -- explicit setting via `/model <provider>` slash command or config file
2. **Availability** -- provider must pass `validate()` health check
3. **Task type** -- certain providers may be preferred for specific task categories (see task-based routing below)
4. **Cost constraints** -- users can configure cost-based routing preferences (max cost per request, preferred free tier)
5. **Failover chain** -- if the primary provider fails, secondary providers are tried in configured order
6. **Session history** -- providers that have failed previously in the session are deprioritized

### 3.2 Configuration

```bash
# Interactive session
siyarix> /model gemini

# Environment variable
export SIYARIX_PROVIDER=openai

# Configuration file (~/.siyarix/config.yaml)
provider: gemini
provider_failover:
  - openai
  - anthropic
  - ollama
```

---

## 4. Failover Behavior

### 4.1 Automatic Failover

When the active provider fails (timeout, authentication error, rate limit, server error):

1. The system logs the failure with provider name, error type, and timestamp
2. If a failover chain is configured, the next available provider is activated
3. The provider health status is updated (session-disabled tracking)
4. The user is notified of the provider switch
5. The original request is retried on the fallback provider
6. If all cloud providers fail, the system falls back to offline heuristic mode

### 4.2 Circuit Breaker Pattern

Each provider has a session-level circuit breaker:

| State | Behavior |
|-------|----------|
| **Closed** | Normal operation; requests pass through |
| **Open** | After configured failures; no requests pass; cooldown timer starts |
| **Half-Open** | After cooldown; a single probe request is allowed to test recovery |

Circuit breaker thresholds are configurable per provider:

```yaml
provider_settings:
  openai:
    circuit_breaker:
      failure_threshold: 3
      cooldown_seconds: 30
```

### 4.3 Exponential Backoff

Failed provider requests are retried with exponential backoff:

- Base delay: 1 second
- Multiplier: 2x
- Max delay: 60 seconds
- Jitter: randomized up to 500ms

### 4.4 Manual Override

Users can force a provider switch at any time via the `/model` slash command, bypassing the automatic selection logic.

### 4.5 Fallback to Offline Mode

If no AI provider is available (all configured providers fail):

- Siyarix falls back to the **Registry (Heuristic)** planner
- Tool execution continues without AI assistance
- Tool discovery, command execution, and output parsing function normally
- Users receive a clear notification that AI planning features are unavailable

---

## 5. Security Boundaries

### 5.1 Local Model Recommendation

Local models are strongly recommended for:

- Classified, sensitive, or proprietary target environments
- Air-gapped networks without external connectivity
- Operations subject to GDPR, CCPA, or other data residency requirements
- Internal corporate networks where data export is prohibited
- High-frequency or bulk operations where API costs are a concern

### 5.2 Provider-Specific Security Notes

| Provider | Data Processing Location | Key Consideration |
|----------|-------------------------|-------------------|
| OpenAI | US (Azure/AWS) | API data may be used for model improvement unless opted out |
| Google Gemini | Google Cloud global | Subject to Google AI Privacy Policy; data may be reviewed |
| Anthropic | US | Privacy-focused; API data not used for training by default |
| Groq | GroqCloud | Review Groq Privacy Policy for data handling practices |
| Together AI | US | Review Together Privacy Policy |
| Azure OpenAI | Customer-chosen region | Enterprise contractual data protection; no training use |
| Ollama | Local (user machine) | No data leaves the host under any circumstances |
| LM Studio | Local (user machine) | No data leaves the host under any circumstances |

---

## 6. API Key Handling

### 6.1 Storage

- All API keys are stored in the **Credential Store** (`credential_store.py`)
- Encryption uses **AES-256-GCM** with a locally derived master key (Argon2id KDF)
- Keys are never stored in source code, committed configuration files, or log output
- The `.env` file (used for runtime convenience) is listed in `.gitignore`

### 6.2 Provisioning

```text
siyarix> /key set gemini <your-api-key>
siyarix> /key set openai <your-api-key>
```

Keys are encrypted immediately upon entry and never appear in shell history or command output.

### 6.3 Rotation

```text
siyarix> /key rotate
```

Key rotation re-encrypts all stored credentials with a new master key. Old encrypted values are purged.

### 6.4 Runtime Handling

- Keys are decrypted only at the moment of use
- Decrypted keys are held in memory for the duration of a single API request
- Keys are not persisted in decrypted form to disk, swap, or core dumps
- Memory containing key material is explicitly zeroed after use where possible

---

## 7. No Hard Dependency on Any Single Provider

- **No provider SDK is a hard runtime dependency.** Optional provider SDKs (`openai`, `google-generativeai`, `anthropic`, etc.) are installed only when the user selects the relevant extras:

  ```bash
  pip install siyarix                # Core only (no AI providers)
  pip install "siyarix[all]"         # All popular providers
  pip install "siyarix[openai]"      # Only OpenAI
  pip install "siyarix[local]"       # Only local providers
  ```

- **The system starts and operates without any AI provider.** Core functionality (Tool Registry, Execution Engine, CLI, REPL) is fully functional offline
- **Heuristic planning** provides basic plan generation and tool selection without any LLM
- **Provider adapters are loaded lazily** -- unused providers do not consume memory, connections, or import time

---

## 8. Logging and Audit

### 8.1 Provider Interaction Logging

All provider interactions are logged with:

- Provider name and model identifier
- Request timestamp and total duration
- Success/failure status with HTTP status code
- Error type (timeout, authentication, rate limit, server error)
- Token usage (prompt, completion, total) where available
- Plan summary (high-level, not full prompts)

### 8.2 Audit Trail

- Provider selections and switches are recorded in the session audit log
- Failover events are logged with cause, provider chain, and resolution
- API key operations (set, rotate, delete) are logged with timestamp and truncated key identifier
- Credential store access attempts are logged

### 8.3 Prompt Storage

By default, full AI prompts and responses are **not** stored in logs. Debug logging (`SIYARIX_LOG_LEVEL=DEBUG`) may capture prompts for troubleshooting purposes. Users are advised to enable debug logging only in controlled environments without sensitive data in prompts.

---

## 9. Prohibited Provider Use

AI providers must not be used through Siyarix to:

- Generate malicious code, payloads, or exploit code targeting unpatched vulnerabilities
- Automate unauthorized access to any system or network
- Process, store, or transmit unauthorized personal data
- Intentionally bypass platform safety mechanisms
- Engage in activities prohibited by the [Ethical Use Policy](ETHICAL_USE.md) or [Responsible AI Use Policy](RESPONSIBLE_AI_USE.md)
- Violate the AI provider's own terms of service or acceptable use policy

---

## 10. Compliance Considerations

Organizations deploying Siyarix should review:

| Framework | Consideration |
|-----------|---------------|
| **EU AI Act** | Risk classification of AI-assisted security operations; transparency obligations |
| **Data Protection (GDPR/CCPA)** | Implications of sending data to cloud AI providers; data processing agreements |
| **Sector Regulations** | PCI-DSS, HIPAA, SOC 2, or sector-specific rules governing AI data processing |
| **Export Control** | AI model access may be subject to export restrictions (EAR, sanctions) |
| **AI Provider Terms** | Each provider's terms of service, data usage policy, and SLA |

---

*This policy supplements the GNU Affero General Public License v3.0 or later. It does not create binding legal obligations beyond applicable law. Consult qualified professionals for regulatory compliance guidance specific to your organization and jurisdiction.*

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
