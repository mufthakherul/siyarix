# Provider Abstraction Layer

The provider abstraction layer decouples Siyarix from any single AI provider, enabling seamless switching, failover, and offline fallback.

## Architecture

```
┌─────────────────────────────────────────┐
│           TaskPlanner / Chat            │
│     (consumer — calls provider API)     │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│          ProviderRegistry               │
│   (ordered by preference, failover)     │
└──┬───┬───┬───┬───┬───┬───┬───┬───┬─────┘
   │   │   │   │   │   │   │   │   │
   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼
  O   G   A   G   T   O   L   C   N
  p   e   n   r   o   l   M   l   o
  e   m   t   o   g   l   S   o   o
  n   i   h   q   e   a   t   u   p
  A   n   r     .   m   u   d   (
  I   i   o           a   d   )
```

## Provider interface

Every provider implements the `Provider` protocol:

```python
class Provider:
    async def plan(self, prompt: str, context: dict) -> dict:
        """Convert natural language to a structured execution plan."""

    async def chat(self, messages: list, max_tokens: int = 4096) -> dict:
        """Multi-turn chat completion."""

    async def validate(self) -> bool:
        """Check if the provider is configured and reachable."""

    async def close(self) -> None:
        """Release resources."""
```

## Registered providers

| Registry name | Adapter | When to use |
|--------------|---------|-------------|
| `openai` | OpenAI GPT-4o | General purpose, high quality |
| `gemini` | Gemini 1.5 Pro | Large context windows, multimodal |
| `anthropic` | Claude 3 Opus | Safety-conscious, complex reasoning |
| `groq` | Groq Llama 3 70B | Low-latency inference |
| `together` | Together Mixtral | Open-weight model aggregation |
| `ollama` | Local Llama 3.1 | Fully offline, no API key needed |
| `lmstudio` | LM Studio (any model) | Local models, GPU-accelerated |
| `cloud` | Configurable cloud endpoint | Enterprise deployments |
| `opencode` | OpenCode-compatible endpoint | Specific platform integration |
| `noop` | Built-in no-op | Offline/testing, no external calls |

## Preference chains

Each provider type has a fallback chain defined in `engine/providers.py`:

```python
PREFERENCE_MAP = {
    "gemini": ["gemini", "openai", "anthropic", "groq", "together",
               "ollama", "lmstudio", "cloud", "noop"],
    "openai": ["openai", "gemini", "anthropic", ...],
    ...
}
```

When `model_provider = "auto"`, the system tries providers in order of availability (API key present + reachable).

## Provider selection

Selection is based on four criteria:

1. **User preference**: The `model_provider` config setting
2. **API key presence**: Provider must have credentials configured
3. **Availability**: Provider must pass `validate()` (endpoint reachable)
4. **Task type**: Some providers may be preferred for specific tasks

## Failover behavior

```
Request → Provider A (preferred)
              │
              ├── Success → Return result
              │
              └── Failure → Circuit breaker records failure
                            │
                            ▼
                    Provider B (next in chain)
                            │
                            ... (continue until noop)
```

- Circuit breaker opens after 3 failures in 60 seconds
- On complete failure, `RuleInterpreter` provides heuristic fallback
- No data loss — unprocessed requests are logged for review

## Security boundaries

| Data type | Before sending to provider | After receiving |
|-----------|---------------------------|-----------------|
| IP addresses | Masked (10.x.x.x) | Unmasked for local use |
| Credentials | Redacted ([REDACTED]) | Permanently redacted |
| API keys | Redacted ([REDACTED]) | Permanently redacted |
| Internal hostnames | Masked (example.com) | Unmasked for local use |

Data masking is enforced by the `MaskingEngine` before any provider call.

## Local/offline operation

Two providers require no API key:

- **Ollama**: `ollama pull llama3.1 && ollama serve`
- **LM Studio**: Start app, enable API server on port 1234

The **noop** provider is always available and provides minimal responses for testing.
