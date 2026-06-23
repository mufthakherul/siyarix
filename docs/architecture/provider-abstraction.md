# Provider Abstraction Layer

The Provider Abstraction Layer decouples all AI-dependent components from specific model backends. It manages 24+ provider profiles with automatic failover, circuit breakers, exponential backoff, token usage tracking, and a unified `OpenAICompat` adapter.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Consumer Layer                     │
│  (Planner, ChatSession, ResponseGenerator, ToolCall  │
│   Repair, AutonomousExecutor, Swarm Agents)          │
└─────────────────────────┬────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────┐
│                    ProviderManager                    │
│                                                      │
│  • Provider selection (preference chain + scoring)   │
│  • Failover orchestration                            │
│  • Circuit breaker management                        │
│  • Rate limiting                                     │
│  • Request/response masking                          │
└──────┬───────────┬───────────┬───────────┬───────────┘
       │           │           │           │
       ▼           ▼           ▼           ▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│OpenAI    │ │Google    │ │Anthropic │ │Ollama    │
│Compat    │ │Gemini    │ │Claude    │ │(local)   │
│Adapter*  │ │Adapter   │ │Adapter   │ │Adapter   │
└──────────┘ └──────────┘ └──────────┘ └──────────┘
       │           │           │           │
       ▼           ▼           ▼           ▼
  24+ Provider Profiles (cloud, local, heuristic fallback)
```

> `*`: The `OpenAICompat` adapter provides a unified OpenAI-compatible API across 14+ providers that support the OpenAI protocol.

---

## Provider Interface

Every provider implements the `Provider` protocol:

```python
class Provider(ABC):
    @abstractmethod
    async def chat(
        self,
        messages: list[dict],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        stream: bool = False
    ) -> ChatResult:
        """Multi-turn chat completion."""

    @abstractmethod
    async def embed(
        self,
        texts: list[str]
    ) -> EmbeddingResult:
        """Generate embeddings for semantic memory."""

    @abstractmethod
    async def validate(self) -> ProviderHealth:
        """Check configuration and endpoint reachability."""

    @abstractmethod
    async def close(self) -> None:
        """Release provider resources."""
```

---

## 24+ Provider Profiles

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
| `zai` | `openai` | Z.AI models |
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

The `OpenAICompat` adapter provides a unified API layer across all providers that support the OpenAI chat completions protocol. This covers 14+ of the 24 providers, enabling a single code path for:

- Chat completions
- Streaming responses
- Embedding generation
- Tool/function calling
- Response format control (JSON mode, structured output)

```python
# Single adapter, multiple providers
adapter = OpenAICompat(provider="openai", api_key=...)
adapter = OpenAICompat(provider="groq", api_key=...)
adapter = OpenAICompat(provider="deepseek", api_key=...)
# All share the same interface
```

---

## ProviderManager

The `ProviderManager` is the central coordinator:

### Selection Logic

Providers are selected based on:

1. **User preference**: `model_provider` config setting
2. **API key presence**: Credential availability via CredentialStore
3. **Availability**: `validate()` health check
4. **Task type**: Some providers preferred for specific tasks (chat vs. embedding)
5. **Cooldown status**: Previously failed providers are skipped

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
              └── Failure → Circuit breaker records failure
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

---

## Circuit Breaker

| Parameter | Default | Description |
|-----------|---------|-------------|
| Failure threshold | 3 | Consecutive failures before opening |
| Recovery timeout | 60s | Time before half-open retry |
| Half-open max requests | 1 | Probe requests during recovery |
| Cooldown duration | 300s | Provider cooldown after circuit open |

```python
breaker = CircuitBreaker(
    failure_threshold=3,
    recovery_timeout=60,
    half_open_max_requests=1,
    cooldown=300
)

state = breaker.record_failure("openai")  # CLOSED → OPEN after 3 failures
state = breaker.record_success("gemini")  # CLOSED or HALF_OPEN → CLOSED
```

---

## ProviderStateManager

Persists provider state across sessions:

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

Stored in SQLite at `~/.siyarix/provider_state.db`. This ensures:
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

When a provider fails with a transient error, the `ProviderManager` applies exponential backoff before retry:

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

## Security & Data Masking

Before any provider call, data is masked by the `MaskingEngine`:

| Data Type | Before Provider | After Receiving |
|-----------|----------------|-----------------|
| IP addresses | `10.x.x.x` | Unmasked for local use |
| Credentials | `[REDACTED]` | Permanently redacted |
| API keys | `[REDACTED]` | Permanently redacted |
| Internal hostnames | `example.com` | Unmasked for local use |
| JWTs / tokens | `[REDACTED]` | Permanently redacted |

Masking is bidirectional for IPs and hostnames (reversible within session), permanent for secrets and credentials.

---

## ModelAliases

The `ModelAliases` system resolves model name variants across providers:

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
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │  Exponential     │  │
                   │  │  Backoff         │  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │  MaskingEngine   │  │
                   │  └──────────────────┘  │
                   └────────┬───────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │OpenAICompat │ │Native       │ │Local        │
    │Adapter      │ │Adapters     │ │Adapters     │
    │(14+         │ │(Gemini,     │ │(Ollama,     │
    │ providers)  │ │ Anthropic,  │ │ LM Studio,  │
    │             │ │ HuggingFace)│ │ llama.cpp)  │
    └─────────────┘ └─────────────┘ └─────────────┘
                            │
                            ▼
                   ┌────────────────────────┐
                   │  ProviderStateManager   │
                   │  (SQLite persistence)   │
                   └────────────────────────┘
                   ┌────────────────────────┐
                   │    UsageTracker         │
                   │  (tokens + cost per     │
                   │   provider)             │
                   └────────────────────────┘
```
