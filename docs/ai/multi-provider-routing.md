# Multi-Provider Routing

Siyarix v3.0.0 supports **24 AI providers**, all accessed through a unified OpenAI-compatible adapter (`openai_compat.py`). The `ProviderManager` singleton manages provider registration, credential pooling, failover, circuit breakers, and cooldown state with exponential backoff.

---

## Supported Providers

| Provider | Type | Env Variable | Default Model | Base URL |
|----------|------|-------------|---------------|----------|
| OpenAI | Cloud | `OPENAI_API_KEY` | gpt-5.5 | (default) |
| Anthropic | Cloud | `ANTHROPIC_API_KEY` | claude-sonnet-4 | (via openai compat) |
| Google Gemini | Cloud | `GEMINI_API_KEY` | gemini-3.5-flash | `generativelanguage.googleapis.com/v1beta/openai/` |
| DeepSeek | Cloud | `DEEPSEEK_API_KEY` | deepseek-v4-flash | `api.deepseek.com` |
| xAI (Grok) | Cloud | `XAI_API_KEY` | grok-4.3 | `api.x.ai` |
| Perplexity | Cloud | `PERPLEXITY_API_KEY` | sonar-pro | `api.perplexity.ai` |
| Groq | Cloud | `GROQ_API_KEY` | llama-4-scout | `api.groq.com/openai/v1` |
| Together AI | Cloud | `TOGETHER_API_KEY` | Llama-4-Scout | `api.together.xyz/v1` |
| OpenRouter | Cloud | `OPENROUTER_API_KEY` | openai/gpt-5.5 | `openrouter.ai/api/v1` |
| Cerebras | Cloud | `CEREBRAS_API_KEY` | gpt-oss-120b | `api.cerebras.ai/v1` |
| Fireworks AI | Cloud | `FIREWORKS_API_KEY` | kimi-k2p6 | `api.fireworks.ai/inference/v1` |
| Mistral AI | Cloud | `MISTRAL_API_KEY` | (from profile) | `api.mistral.ai` |
| Z.AI | Cloud | `ZAI_API_KEY` | glm-5.1 | `api.z.ai/api/paas/v4` |
| MiniMax | Cloud | `MINIMAX_API_KEY` | MiniMax-M3 | `api.minimax.io/v1` |
| Moonshot | Cloud | `MOONSHOT_API_KEY` | kimi-k2.6 | `api.moonshot.ai/v1` |
| NVIDIA NIM | Cloud | `NVIDIA_API_KEY` | Nemotron-3-Super | `integrate.api.nvidia.com/v1` |
| HuggingFace | Cloud | `HUGGINGFACE_API_KEY` | (varies) | `api-inference.huggingface.co/v1` |
| Azure OpenAI | Cloud | `AZURE_OPENAI_API_KEY` | gpt-5.5 | (user-configured) |
| OpenCodeGo | Cloud | `OPENCODE_GO_API_KEY` | deepseek-v4-flash | `opencode.ai/zen/go/v1` |
| Ollama | Local | — | drana-infinity-7b | `localhost:11434/v1` |
| LM Studio | Local | — | (varies) | `localhost:1234` |
| llama.cpp | Local | — | (varies) | `localhost:18080` |
| vLLM | Local | — | (varies) | `localhost:8000` |
| LocalAI | Local | — | (varies) | `localhost:8080` |
| Registry | Heuristic | — | — | — |

---

## Architecture

```
User Input → _execute_instruction()
                │
                ▼
         ProviderManager.select_provider(preferred)
                │
                ▼
         ┌──────────────┐
         │  Provider A  │ ← preferred (user config or auto-detect)
         │  (primary)   │
         └──────┬───────┘
                │
        ┌─── Success ────→ Return result
        │
        └─── Failure ────→ ProviderManager.classify_error()
                           ├── AUTH → mark credential "dead"
                           ├── RATE_LIMIT → exponential backoff
                           ├── TIMEOUT → retry with backoff
                           ├── CONTEXT_OVERFLOW → compact and retry
                           ├── MODEL_NOT_FOUND → fallback model
                           └── SERVER_ERROR → circuit breaker
                                    │
                                    ▼
                           ProviderStateManager.record_failure()
                           (persistent cooldown across restarts)
```

---

## Provider Manager (Singleton)

`ProviderManager` is a thread-safe singleton that centralises all provider logic:

```python
from siyarix.providers import ProviderManager

pm = ProviderManager.get_instance()
```

### Registration

All 24 providers register via profile objects in `src/siyarix/providers/profiles/`:

```python
pm.register(ProviderProfile(
    name="openai",
    display_name="OpenAI",
    default_model="gpt-5.5",
    api_key_env="OPENAI_API_KEY",
    base_url="",
    supports_streaming=True,
    supports_tools=True,
    supports_vision=True,
    cost_tier=CostTier.MEDIUM,
    provider_type=ProviderType.CLOUD,
    # ...
))
```

### Auto-Detect

When `model_provider = "auto"`, `ProviderManager.auto_detect_provider()` scans profiles in priority order:

```python
def auto_detect_provider(self) -> str | None:
    for profile in self.list_profiles():
        if resolve_api_key(profile.name, profile.api_key_env):
            return profile.name
        if profile.provider_type == ProviderType.LOCAL and profile.base_url:
            return profile.name
    return None
```

### Preference Ordering

`list_profiles()` respects `provider_priority` from `settings.toml`:

```toml
provider_priority = "openai, gemini, anthropic, groq"
```

Providers are sorted by (index in priority list, -priority).

---

## Error Classification & Failover

### Classification Routes

`ProviderManager.classify_error()` uses a multi-pass strategy:

1. **HTTP status code** → maps to `FailoverReason`
2. **Error message text** → scans for keywords ("rate limit", "timeout", "401", etc.)
3. **Credential rotation** hints returned for auth/billing failures

```python
@dataclass
class ClassifiedError:
    reason: FailoverReason
    retryable: bool = True
    should_rotate_credential: bool = False
    should_fallback: bool = False
    should_compress: bool = False
    message: str = ""
```

### Failover Reasons

| Reason | HTTP Status | Retryable | Action |
|--------|------------|-----------|--------|
| `AUTH` | 401, 403 | No | Mark credential dead, rotate |
| `RATE_LIMIT` | 429 | Yes | Exponential backoff (10s→20s→40s→...→3600s) |
| `BILLING` | 402 | No | Mark credential dead |
| `TIMEOUT` | 408 | Yes | Backoff (5s→10s→...→300s) |
| `SERVER_ERROR` | 500, 502, 503, 504, 529 | Yes | Backoff (5s→10s→...→300s) |
| `CONTEXT_OVERFLOW` | — | Yes | Compact history, retry |
| `MODEL_NOT_FOUND` | 404 | No | Fall back to alternative model |
| `UNKNOWN` | — | No | Propagate error |

### Exponential Backoff

Per-credential cooldown with exponential backoff:

```python
# PROV-02: Exponential backoff for rate limits
backoff = min(3600, 10 * (2**credential.failure_count))
credential.cooldown_until = time.time() + backoff
```

---

## Provider State Manager

`ProviderStateManager` persists cooldown/failure state across restarts to `provider_state.json`:

```python
COOLDOWN_STEPS = [30.0, 60.0, 300.0]
MAX_COOLDOWN = 300.0
```

### Skip-Known-Bad Cache

Per-session cache that remembers failing `(provider, model)` pairs for 5 minutes:

```python
state_manager.mark_skip_candidate(session_id, "openai", "gpt-4")
state_manager.is_candidate_skipped(session_id, "openai", "gpt-4")  # True for 5 min
```

### Availability Checks

```python
pm.get_available_providers(preferred=["openai", "gemini"])
# Returns only non-cooldown providers, preferred ones first
```

---

## Credential Resolution

`resolve_api_key()` is the canonical key-resolution function, with three-tier fallback:

1. **Credential Store** — `CredentialStore.retrieve(provider, "api_key")`
2. **Environment Variable** — `PROVIDER_API_KEY` or profile-specific env var
3. **Empty string** — local providers (Ollama, LM Studio) may not need a key

```python
def resolve_api_key(provider: str, env_var: str | None = None) -> str | None:
    # 1. Try credential store
    # 2. Try environment variable
    # 3. Return None
```

Per-provider env variables are defined in `openai_compat.py:PROVIDER_CONFIG`.

---

## Retry Strategy

The OpenAI-compatible adapter (`make_openai_adapter`) implements retry with **context compaction**:

```python
for attempt in range(max_retries):
    try:
        return await openai_complete(client, model, ...)
    except Exception as e:
        classified = pm.classify_error(provider, e, http_status=status_code)

        if classified.should_compress and history:
            # Compact long context and retry
            compactor = CompactionEngine()
            result = await compactor.compact(history)
            continue

        if classified.retryable and attempt < max_retries - 1:
            pm.record_failure(provider, classified.reason)
            await asyncio.sleep(2 ** attempt)  # 1s, 2s, 4s
            continue

        pm.record_failure(provider, classified.reason)
        raise
```

---

## Provider Profiles

Each provider profile defines:

```python
@dataclass
class ProviderProfile:
    name: str                      # Internal identifier
    display_name: str              # Human-readable name
    models: list[ModelInfo]        # Supported models
    default_model: str             # Default model ID
    api_key_env: str               # Environment variable name
    base_url: str                  # API base URL
    supports_streaming: bool       # Streaming support
    supports_tools: bool           # Function/tool calling
    supports_vision: bool          # Image inputs
    cost_tier: CostTier            # FREE / LOW / MEDIUM / HIGH
    provider_type: ProviderType    # CLOUD or LOCAL
    priority: int                  # Preference ordering
    fallback_models: list[str]     # Alternative models
```

Profiles are registered by individual files in `src/siyarx/providers/profiles/` (each ~50–80 lines).

---

## Health Check

```bash
siyarix health
```

Checks all configured providers, reporting status (available/unavailable), latency, and error counts.

---

## Related Modules

| Module | Path | Purpose |
|--------|------|---------|
| `ProviderManager` | `src/siyarix/providers/manager.py` | Singleton provider registry, failover, ensemble |
| `ProviderStateManager` | `src/siyarix/providers/state.py` | Persistent cooldown state, skip-known-bad cache |
| `UsageTracker` | `src/siyarix/providers/usage.py` | Token usage and cost estimation |
| `ProviderProfile` / `ProviderType` | `src/siyarix/providers/types.py` | Data models for provider metadata |
| `openai_compat.py` | `src/siyarix/chat/openai_compat.py` | Universal OpenAI-compatible adapter |
| `detect_compat()` | `src/siyarix/chat/openai_compat.py:169` | Auto-detect provider capabilities |
| `profiles/` | `src/siyarix/providers/profiles/` | 24 individual provider profiles |
