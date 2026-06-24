# Provider Abstraction Layer

The Provider Abstraction Layer decouples all AI-dependent components from specific model backends. It manages 26 provider profiles with automatic failover, circuit breaking, exponential backoff, token usage tracking, and a unified `OpenAICompat` adapter. Provider state is persisted as JSON for cross-session continuity.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                Consumer Layer                         │
│  (Planner, ChatSession, AutonomousExecutor, Swarm)   │
└─────────────────────────┬────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────┐
│                   ProviderManager                     │
│                                                      │
│  • Provider selection (preference chain + scoring)   │
│  • Failover orchestration                            │
│  • Circuit breaking (record_failure)                 │
│  • Rate limiting                                     │
│  • DLP data redaction                                │
│  • Provider filtering by capability                  │
└──────┬───────────┬───────────┬───────────┬──────────┘
       │           │           │           │
       ▼           ▼           ▼           ▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│OpenAI    │ │Ollama    │ │LM Studio │ │llama.cpp │
│Compat    │ │Utils     │ │(OpenAI   │ │(OpenAI   │
│Adapter*  │ │(local)   │ │Compat)   │ │Compat)   │
└──────────┘ └──────────┘ └──────────┘ └──────────┘
       │           │
       ▼           ▼
  26 Provider Profiles (cloud, local, heuristic fallback)
```

> `*`: The `OpenAICompat` adapter (`siyarix/chat/openai_compat.py`) provides a unified OpenAI-compatible API across all providers that support the OpenAI chat completions protocol.

---

## Provider Interface

Providers are defined as data profiles rather than abstract base classes. The types module (`siyarix/providers/types.py`) provides the core data models:

```python
@dataclass
class ProviderProfile:
    name: str
    display_name: str
    provider_type: str           # "cloud" | "local" | "heuristic"
    base_url: str
    api_key_env: str | None      # Environment variable name
    models: list[ModelInfo]
    capabilities: set[str]       # "chat", "embed", "function_calling", "vision", etc.
    priority: int                # Position in preference chain
    rate_limit: int | None = None
    timeout: int = 60
```

```python
@dataclass
class ModelInfo:
    id: str
    display_name: str
    context_window: int
    max_output_tokens: int
    capabilities: set[str]       # "chat", "vision", "function_calling", "json_mode"
```

### Provider Selection

Providers can be filtered by capability:

```python
# Get providers with specific capabilities
vision_providers = pm.get_providers_by_capability("vision")
free_providers = pm.get_providers_by_capability("free")
local_providers = pm.get_providers_by_capability("local")
fn_call_providers = pm.get_providers_by_capability("function_calling")
```

---

## 26 Provider Profiles

### Cloud Providers (API Key Required)

| Registry Name | SDK / API | Notable Models |
|--------------|-----------|----------------|
| `openai` | `openai` | GPT-4o, GPT-4-turbo, GPT-3.5-turbo |
| `gemini` | `google-generativeai` | Gemini 2.0 Flash, 1.5 Pro |
| `anthropic` | `anthropic` | Claude 3.5 Sonnet, Claude 3 Opus |
| `groq` | `groq` | Llama 3 70B, Mixtral 8x7B |
| `together` | `together` | Mixtral, DeepSeek, Llama variants |
| `openrouter` | `openai` | Multi-model router |
| `deepseek` | `openai` | DeepSeek-V2, DeepSeek-Coder |
| `xai` | `openai` | Grok |
| `mistral` | `mistralai` | Mistral Large, Mistral Small |
| `perplexity` | `openai` | Sonar, Sonar-Pro |
| `cerebras` | `openai` | Fast inference models |
| `fireworks` | `openai` | Open model serving |
| `zai` | `openai` | Z.A.I. models |
| `minimax` | `openai` | MiniMax models |
| `moonshot` | `openai` | Moonshot / Kimi |
| `nvidia` | `openai` | NVIDIA Nemotron |
| `huggingface` | `huggingface-hub` | Hugging Face Inference API |
| `azure` | `openai` | Azure OpenAI (enterprise, managed AD) |
| `opencode_zen` | `openai` | OpenCode Zen backend |

### Local Providers (No API Key)

| Registry Name | Default Endpoint | Notes |
|--------------|-----------------|-------|
| `ollama` | `http://localhost:11434` | Pull any open-weight model |
| `lmstudio` | `http://localhost:1234` | GUI + API server |
| `llamacpp` | `http://localhost:8080` | Efficient CPU/GPU inference |
| `vllm` | Configurable | High-throughput GPU serving |
| `localai` | `http://localhost:8080` | Drop-in OpenAI replacement |

### Heuristic Fallback

| Name | Description |
|------|-------------|
| `registry` | RegistryPlanner — no AI, always available, offline-safe |

---

## OpenAICompat Adapter

The `OpenAICompat` adapter (`siyarix/chat/openai_compat.py`) provides a unified API layer across all providers that support the OpenAI chat completions protocol. This covers 14+ providers, enabling a single code path for:

- Chat completions
- Streaming responses
- Embedding generation
- Tool/function calling
- Response format control (JSON mode, structured output)

```python
adapter = OpenAICompat(provider="openai", api_key=...)
adapter = OpenAICompat(provider="groq", api_key=...)
adapter = OpenAICompat(provider="deepseek", api_key=...)
```

---

## ProviderManager

The `ProviderManager` in `siyarix/providers/manager.py` is the central coordinator:

### Selection Logic

Providers are selected based on:

1. **User preference**: `model_provider` config setting
2. **API key presence**: Credential availability via CredentialStore
3. **Availability**: Health check and connectivity test
4. **Task requirements**: Capability matching (vision, function calling, etc.)
5. **Cooldown status**: Previously failed providers are skipped
6. **Timeout/error history**: Providers with high error rates are deprioritized

### Preference Chain

When `model_provider = "auto"`, the system traverses the preference chain in order, skipping any provider that is in cooldown or circuit-broken:

```
gemini → openai → anthropic → groq → together → openrouter → deepseek → xai →
mistral → perplexity → cerebras → fireworks → zai → minimax → moonshot →
nvidia → huggingface → azure → opencode_zen → ollama → lmstudio → llamacpp →
vllm → localai → registry (heuristic)
```

### Failover Behavior

```
Request → Provider A (preferred)
              │
              ├── Success → Return result, record success
              │
              └── Failure → record_failure()
                            │
                            ▼
                    ProviderStateManager records cooldown
                            │
                            ▼
                    Provider B (next in chain)
                            │
                            ├── Success → Return result
                            │
                            └── Failure → Continue chain
                                          │
                                          ▼
                                  Registry (heuristic fallback)
```

### Stats

```python
stats = provider_manager.stats()
# Returns usage statistics, error rates, current state for all providers
```

---

## Circuit Breaking

Circuit-breaking is handled by `ProviderManager.record_failure()`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| Failure threshold | 3 | Consecutive failures before opening |
| Recovery timeout | 60s | Time before half-open retry |
| Cooldown duration | 300s | Provider cooldown after circuit open |

```python
state = provider_manager.record_failure("openai")  # CLOSED → OPEN after 3 failures
state = provider_manager.record_success("gemini")  # CLOSED or HALF_OPEN → CLOSED
```

---

## ProviderStateManager

Persists provider state across sessions using JSON:

```python
@dataclass
class ProviderState:
    provider_name: str
    circuit_state: str                # CLOSED | OPEN | HALF_OPEN
    failure_count: int
    last_failure: datetime | None
    cooldown_until: datetime | None
    rate_limited_until: datetime | None
    total_requests: int
    total_tokens: int
    total_cost: float
```

Stored in `provider_state.json` at the config directory. This ensures:
- Failed providers remain in cooldown across restarts
- Rate-limited providers are skipped until reset
- Cost tracking persists across sessions

---

## UsageTracker

Tracks token usage and cost per provider:

| Metric | Tracked Per |
|--------|-------------|
| Prompt tokens | Request |
| Completion tokens | Response |
| Total tokens | Request + response |
| Estimated cost | Provider rate card |
| Request count | Per session |
| Latency | Per request |

```python
tracker = UsageTracker()
tracker.record("openai", prompt_tokens=150, completion_tokens=450, latency=2.3)
summary = tracker.get_summary("openai")
# UsageSummary(total_tokens=600, total_cost=0.009, avg_latency=2.3, request_count=1)
```

---

## Exponential Backoff

When a provider fails with a transient error, exponential backoff is applied:

```python
backoff = min(2 ** attempt + random.uniform(0, JITTER), MAX_DELAY)
```

| Attempt | Delay Range | Max Delay |
|---------|-------------|-----------|
| 1 | 1.0–2.0s | 30s |
| 2 | 2.0–3.0s | 30s |
| 3 | 4.0–5.0s | 30s |
| 4 | 8.0–9.0s | 30s |
| 5+ | 16.0–17.0s | 30s |

---

## Ollama Utilities

`siyarix/providers/ollama_utils.py` provides Ollama-specific helpers:

- Model discovery via `ollama list`
- Model pulling with progress tracking
- Endpoint health checks
- Automatic model selection based on available hardware

---

## Security & Data Masking

The `DLPEngine` in `siyarix/dlp.py` handles data masking before provider calls:

| Data Type | Before Provider | After Receiving |
|-----------|----------------|-----------------|
| IP addresses | `10.x.x.x` | Unmasked for local use |
| Credentials | `[REDACTED]` | Permanently redacted |
| API keys | `[REDACTED]` | Permanently redacted |
| Internal hostnames | `example.com` | Unmasked for local use |
| JWTs / tokens | `[REDACTED]` | Permanently redacted |

---

## ModelAliases

The `ModelAliases` system in `siyarix/model_aliases.py` resolves model name variants:

| Alias | Resolves To |
|-------|-------------|
| `gpt-4` | `gpt-4-turbo`, `gpt-4o` (precedence order) |
| `claude-3` | `claude-3-opus`, `claude-3-sonnet` |
| `gemini-pro` | `gemini-1.5-pro`, `gemini-2.0-flash` |
| `llama-3` | `llama-3-70b`, `llama-3-8b` |
| `mixtral` | `mixtral-8x7b`, `mixtral-8x22b` |

---

## Component Relationships

```
                   ┌────────────────────────┐
                   │     Consumer Layer      │
                   │  (Planner, Chat, etc.)  │
                   └────────┬───────────────┘
                            │
                            ▼
                   ┌────────────────────────┐
                   │    ProviderManager      │
                   │                        │
                   │  ┌──────────────────┐  │
                   │  │  Preference Chain│  │
                   │  │  + Failover      │  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │  Circuit Breaker │  │
                   │  │  (record_failure)│  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │  Exponential     │  │
                   │  │  Backoff         │  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │  DLP Redaction   │  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │  Capability      │  │
                   │  │  Filtering       │  │
                   │  └──────────────────┘  │
                   └────────┬───────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │OpenAICompat  │ │ProviderState │ │  Ollama      │
    │Adapter       │ │ Manager      │ │  Utils       │
    │(14+ providers)│ │ (JSON file)  │ │ (local)      │
    └──────────────┘ └──────────────┘ └──────────────┘
                            │
                            ▼
                   ┌────────────────────────┐
                   │    UsageTracker         │
                   │  (tokens + cost per     │
                   │   provider)             │
                   └────────────────────────┘
```
