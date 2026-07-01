# 🔀 Multi-Provider Routing

!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Siyarix boasts robust support for **25 AI providers** (24 cloud/local + 1 offline registry), all accessible through a unified, OpenAI-compatible adapter located in `openai_compat.py`.

At the heart of this system is the `ProviderManager` singleton. Think of it as the air traffic controller for your AI requests—it handles provider registration, credential pooling, seamless failover, exponential-backoff cooldowns, and smart multi-model ensemble decisions.

---

## 🌐 Supported Providers

Siyarix integrates with a wide array of top-tier AI providers. Here's a quick look at what's supported out of the box:

| Provider | Type | Env Variable | Default Model | Base URL |
|----------|------|-------------|---------------|----------|
| OpenAI | Cloud | `OPENAI_API_KEY` | gpt-5.5 | (default) |
| Anthropic | Cloud | `ANTHROPIC_API_KEY` | claude-sonnet-4-6 | (via openai compat) |
| Google Gemini | Cloud | `GEMINI_API_KEY` | gemini-3.1-pro-preview | `generativelanguage.googleapis.com/v1beta/openai/` |
| DeepSeek | Cloud | `DEEPSEEK_API_KEY` | deepseek-v4-flash | `api.deepseek.com` |
| xAI (Grok) | Cloud | `XAI_API_KEY` | grok-4.1 | `api.x.ai` |
| Perplexity | Cloud | `PERPLEXITY_API_KEY` | sonar-pro | `api.perplexity.ai` |
| Groq | Cloud | `GROQ_API_KEY` | llama-4-scout | `api.groq.com/openai/v1` |
| Together AI | Cloud | `TOGETHER_API_KEY` | Llama-4-Scout | `api.together.xyz/v1` |
| OpenRouter | Cloud | `OPENROUTER_API_KEY` | openai/gpt-5.5 | `openrouter.ai/api/v1` |
| Cerebras | Cloud | `CEREBRAS_API_KEY` | gpt-oss-120b | `api.cerebras.ai/v1` |
| Fireworks AI | Cloud | `FIREWORKS_API_KEY` | kimi-k2.6 | `api.fireworks.ai/inference/v1` |
| Mistral AI | Cloud | `MISTRAL_API_KEY` | (from profile) | `api.mistral.ai` |
| Z.AI | Cloud | `ZAI_API_KEY` | glm-5.1 | `api.z.ai/api/paas/v4` |
| MiniMax | Cloud | `MINIMAX_API_KEY` | MiniMax-M3 | `api.minimax.io/v1` |
| Moonshot | Cloud | `MOONSHOT_API_KEY` | kimi-k2.6 | `api.moonshot.ai/v1` |
| NVIDIA NIM | Cloud | `NVIDIA_API_KEY` | Nemotron-3-Super | `integrate.api.nvidia.com/v1` |
| HuggingFace | Cloud | `HUGGINGFACE_API_KEY` | (varies) | `api-inference.huggingface.co/v1` |
| Azure OpenAI | Cloud | `AZURE_OPENAI_API_KEY` | gpt-5.5 | (user-configured) |
| OpenCodeZen | Cloud | `OPENCODE_API_KEY` | deepseek-v4-flash | `opencode.ai/zen/v1` |
| Ollama | Local | — | llama3.1 | `localhost:11434/v1` |
| LM Studio | Local | — | (varies) | `localhost:1234/v1` |
| llama.cpp | Local | — | (varies) | `localhost:18080/v1` |
| vLLM | Local | — | (varies) | `localhost:8000/v1` |
| LocalAI | Local | — | (varies) | `localhost:8080/v1` |
| Registry | Heuristic | — | — | — |

!!! tip
    Local providers like Ollama, LM Studio, and others typically don't require an API key environment variable. Siyarix is smart enough to handle them seamlessly!

---

## 🏗️ Architecture

Understanding how Siyarix routes a user request can help you debug and optimize your configuration. Here's a simplified flow:

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
                           └── SERVER_ERROR → record_failure with cooldown
                                    │
                                    ▼
                           ProviderStateManager.record_failure()
                           (persistent cooldown across restarts via JSON)
```

!!! note
    The `ProviderStateManager` ensures that failure cooldowns persist even if you restart Siyarix, preventing endless retry loops on failing APIs.

---

## 🎛️ Provider Manager (Singleton)

The `ProviderManager` is a thread-safe singleton, meaning there's only ever one instance running, and it safely handles requests from multiple threads. It centralizes all provider logic.

```python
from siyarix.providers import ProviderManager

pm = ProviderManager.get_instance()
```

### 📝 Registration

All 25 providers are registered using individual profile files located in `src/siyarix/providers/profiles/`. This modular approach makes it super easy to add new providers in the future.

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
    cost_tier=CostTier.HIGH,
    provider_type=ProviderType.CLOUD,
    priority=10,
    docs_url="https://platform.openai.com/docs/models",
))
```

Each profile defines its supported models using the `ModelInfo` dataclass, ensuring Siyarix knows exactly what each model is capable of:

```python
ModelInfo(
    name="gpt-5.5",
    supports_vision=True,
    supports_structured_output=True,
    supports_function_calling=True,
    context_window=1050000,
    cost_tier=CostTier.HIGH,
)
```

### 🕵️ Auto-Detect

If you set `model_provider = "auto"`, Siyarix isn't just guessing. `ProviderManager.auto_detect_provider()` intelligently scans through profiles based on priority, looking for configured API keys or running local endpoints.

```python
def auto_detect_provider(self) -> str | None:
    for profile in self.list_profiles():
        if resolve_api_key(profile.name, profile.api_key_env):
            return profile.name
        if profile.provider_type == ProviderType.LOCAL and profile.base_url:
            return profile.name
    return None
```

### ⚖️ Preference Ordering

You can control the priority of providers via your `settings.toml` file. The `list_profiles()` function respects this configuration.

```toml
provider_priority = "openai, gemini, anthropic, groq"
```

Providers are sorted first by their index in your priority list, and then by their default priority score.

---

## 📦 Provider Data Models

To keep things organized, all data structures representing providers and models are stored in `src/siyarix/providers/types.py`.

### ProviderProfile
This defines everything Siyarix needs to know about a provider.

```python
@dataclass
class ProviderProfile:
    name: str                          # Internal identifier (e.g. "openai")
    display_name: str                  # Human-readable name
    models: list[ModelInfo]            # Supported models with capability metadata
    default_model: str                 # Fallback model for this provider
    api_key_env: str                   # Environment variable for API key
    base_url: str                      # API base URL
    supports_streaming: bool           # Streaming support
    supports_tools: bool               # Function/tool calling
    supports_vision: bool              # Image input support
    supports_structured_output: bool   # JSON structured output mode
    sdk_dependency: str                # Optional SDK package requirement
    max_tokens: int                    # Max output tokens
    max_context_tokens: int            # Max context window size
    priority: int                      # Preference ordering
    cost_tier: CostTier                # FREE / LOW / MEDIUM / HIGH
    provider_type: ProviderType        # CLOUD or LOCAL
    fallback_models: list[str]         # Alternative models to try on failure
    docs_url: str                      # Link to provider documentation
```

### ProviderCredential
This keeps track of API keys, URLs, and the current health status of the credential.

```python
@dataclass
class ProviderCredential:
    provider: str
    api_key: str = ""
    base_url: str = ""
    status: str = "active"             # "active", "dead", or "cooldown"
    cooldown_until: float = 0.0
    failure_count: int = 0
    last_used: float = 0.0

    @property
    def is_available(self) -> bool:
        # True unless dead, in cooldown, or missing both key and URL
```

### ModelInfo
Details the specific capabilities of an individual model.

```python
@dataclass
class ModelInfo:
    name: str
    supports_vision: bool = False
    supports_tools: bool = True
    supports_structured_output: bool = False
    supports_function_calling: bool = True
    context_window: int = 8192
    cost_tier: CostTier = CostTier.MEDIUM
```

### 🏷️ Enums
We use standardized enums to keep categories consistent:
- **FailoverReason**: `AUTH`, `RATE_LIMIT`, `BILLING`, `TIMEOUT`, `SERVER_ERROR`, `CONTEXT_OVERFLOW`, `MODEL_NOT_FOUND`, `UNKNOWN`
- **CostTier**: `FREE`, `LOW`, `MEDIUM`, `HIGH`
- **ProviderType**: `CLOUD`, `LOCAL`

### ClassifiedError
When something goes wrong, it's classified into an actionable format.

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

---

## 🛡️ Error Classification & Failover

Robust error handling is critical when working with external APIs. Siyarix is designed to handle hiccups gracefully.

### Classification Strategy

When an API call fails, `ProviderManager.classify_error()` kicks into action using a multi-pass strategy:
1. **HTTP status code**: Quickly maps standard errors (like 429 for rate limits) to a `FailoverReason`.
2. **Error message text**: Scans the error response for keywords (e.g., "rate limit", "timeout", "401").
3. **Credential rotation hints**: Detects auth or billing failures to trigger credential rotation.

### Failover Reasons & Actions

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

!!! warning
    If a credential fails due to `AUTH` or `BILLING` issues, Siyarix marks it as "dead" to prevent burning through retries and instantly pivots to a fallback provider.

### Failure Recording (Circuit Breaking)

`ProviderManager.record_failure()` is Siyarix's built-in circuit breaker:
- **AUTH/BILLING**: Immediate halt. No further attempts with this credential.
- **RATE_LIMIT**: Calculates an exponential backoff time (up to an hour) to let the API recover.
- **TIMEOUT/SERVER_ERROR**: Uses a shorter backoff curve (up to 5 minutes) since these are often temporary glitches.

```python
pm.record_failure(provider, classified.reason)
```

### Per-Session "Skip-Known-Bad" Cache

Nobody likes waiting for the same failing model over and over. `ProviderStateManager` keeps a short-term memory (5 minutes) of failing `(provider, model)` combos to skip them entirely.

```python
state_manager.mark_skip_candidate(session_id, "openai", "gpt-5.5")
state_manager.is_candidate_skipped(session_id, "openai", "gpt-5.5")  # True for 5 min
```

### Availability Checks

Need to know who's ready to work?

```python
pm.get_available_providers(preferred=["openai", "gemini"])
# Returns only non-cooldown providers, with preferred ones at the top of the list
```

---

## 💾 Provider State Manager

API state shouldn't be lost when you restart the app. The `ProviderStateManager` persists cooldown and failure states to a lightweight **JSON file** (`provider_state.json`).

```python
COOLDOWN_STEPS = [30.0, 60.0, 300.0]
MAX_COOLDOWN = 300.0
```

This ensures that if you hit an hour-long rate limit, restarting Siyarix won't accidentally hammer the API again. It tracks:
- **`disabled`**: Timestamps for when cooldowns expire.
- **`failure_counts`**: How many times a provider has failed consecutively.
- **`last_fail_time`**: When the most recent failure happened.

```python
state_manager.record_failure(provider, reason)  # Saves to JSON automatically
state_manager.record_success(provider)           # Clears cooldown status
state_manager.is_disabled(provider)              # Checks if still in cooldown
state_manager.cooldown_remaining(provider)       # Time left until ready
```

---

## 🔑 Credential Resolution

Finding the right API key is handled by `resolve_api_key()`. It uses a smart, three-tier fallback approach:

1. **Credential Store**: Checks the secure `CredentialStore` (`CredentialStore.retrieve(provider, "api_key")`).
2. **Environment Variable**: Looks for standard env vars like `OPENAI_API_KEY`.
3. **Empty String**: Allows local providers (like Ollama) to proceed without a key.

```python
def resolve_api_key(provider: str, env_var: str | None = None) -> str | None:
    # 1. Try credential store
    # 2. Try environment variable
    # 3. Return None
```

---

## 🪪 Model ID Normalization

Model names change, and standardizing them is crucial. `model_aliases.py` ensures that no matter what the user types, Siyarix knows the correct internal name.

```python
from siyarix.model_aliases import normalize_model_id, resolve_alias, list_aliases, register_alias

model = normalize_model_id("anthropic", "claude-opus-4.8")  # → "claude-opus-4-8"
model = normalize_model_id("gemini", "gemini-3-pro")        # → "gemini-3.1-pro-preview"
model = normalize_model_id("deepseek", "deepseek-v4")       # → "deepseek-v4-flash"
```

---

## 🦙 Ollama Utilities

Working with local models should be frictionless. `ollama_utils.py` provides helpers to ensure Ollama is running when you need it.

```python
from siyarix.providers.ollama_utils import ensure_ollama_running

# Launches Ollama in background if configured and not already running
ensure_ollama_running()
```

!!! tip
    Siyarix can automatically launch Ollama if `model_provider` is set to `"ollama"` or if `_start_ollama_on_launch` is enabled in your settings!

---

## 🎯 Provider Selection

Need to ask an AI a question? Here's how Siyarix decides who gets the job.

```python
# Auto-detect the first available provider
provider, model = pm.select_provider(preferred=None)

# Explicitly request a specific provider
provider, model = pm.select_provider(preferred="openai")
```

### Capability-Based Filtering

You can also ask Siyarix for providers that meet specific criteria:

```python
# Get all cloud providers supporting function calling
providers = pm.get_providers_by_capability(function_calling=True, local=False, free=False)

# Get only free-tier local providers
free_local = pm.get_providers_by_capability(free=True, local=True)

# Get vision-capable providers
vision_providers = pm.get_providers_by_capability(vision=True)
```

---

## 📊 Usage Tracking

Keep an eye on your API costs! The `UsageTracker` (found in `usage.py`) monitors token consumption and estimates costs per provider.

```python
from siyarix.providers import UsageTracker

tracker = UsageTracker()
tracker.record_call("openai", "gpt-5.5", input_tokens=500, output_tokens=150, cost_tier=CostTier.HIGH)
print(tracker.summary())
# LLM calls: 1 | Tokens: 500↑ 150↓ | Est. cost: $0.0086
```

!!! info
    Usage statistics are persisted to JSON, allowing you to track costs and token limits across multiple sessions.

---

## 🩺 Health Check

Wondering if your providers are online? Run the health check command:

```bash
siyarix health
```

This command pings all configured providers and reports back on their availability, latency, and any recent errors.

---

## 📈 Provider Statistics

For programmatic access to provider health:

```python
stats = pm.stats()
# {
#     "total_providers": 25,
#     "credentials": {"openai": 1, "anthropic": 0, ...},
#     "error_counts": {"openai": 3},
# }
```

---

## 📁 Related Modules

Want to dive deeper into the code? Here is where everything lives:

| Module | Path | Purpose |
|--------|------|---------|
| `ProviderManager` | `src/siyarix/providers/manager.py` | Singleton provider registry, failover, ensemble, stats |
| `ProviderStateManager` | `src/siyarix/providers/state.py` | Persistent cooldown state (JSON-based), skip-known-bad cache |
| `UsageTracker` | `src/siyarix/providers/usage.py` | Token usage and cost estimation |
| `ProviderProfile` / `ModelInfo` | `src/siyarix/providers/types.py` | Data models for provider metadata |
| `openai_compat.py` | `src/siyarix/chat/openai_compat.py` | Universal OpenAI-compatible adapter |
| `normalize_model_id` | `src/siyarix/model_aliases.py` | Model ID normalization and alias resolution |
| `ensure_ollama_running` | `src/siyarix/providers/ollama_utils.py` | Ollama background launcher |
| `profiles/` | `src/siyarix/providers/profiles/` | 25 individual provider profiles |
