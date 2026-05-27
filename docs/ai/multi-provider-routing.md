# Multi-Provider Routing

Siyarix routes requests across 10 AI providers with automatic failover, circuit breakers, and heuristic fallback.

## Routing architecture

```
User Input → TaskPlanner
               │
               ▼
        ProviderRegistry.ordered_by_preference()
               │
               ▼
        ┌──────────────┐
        │  Provider A  │ ← preferred (user config or "auto")
        │  (primary)   │
        └──────┬───────┘
               │
       ┌─── Success ────→ Return result
       │
       └─── Failure ────→ Circuit breaker records
                          (3 failures = OPEN for 60s)
                          │
                          ▼
                    ┌──────────────┐
                    │  Provider B  │ ← next in chain
                    │  (fallback)  │
                    └──────┬───────┘
                           │
                    (continue until noop)
```

## Provider registration

Providers are registered in `providers.py`:

```python
@dataclass
class ProviderRegistry:
    _class_providers: dict[str, type[Provider]]
    _instance_providers: dict[str, Provider]
```

Registration supports both class-based (factory creates per-request) and instance-based (singleton) patterns.

## Preference chain

`engine/providers.py` defines ordered fallback chains per provider type:

```python
PREFERENCE_MAP = {
    "gemini":   ["gemini", "openai", "anthropic", "groq", "together",
                 "ollama", "lmstudio", "cloud", "noop"],
    "openai":   ["openai", "gemini", "anthropic", "groq", "together",
                 "ollama", "lmstudio", "cloud", "noop"],
    "anthropic":["anthropic", "openai", "gemini", "groq", "together",
                 "ollama", "lmstudio", "cloud", "noop"],
    "auto":     "...preference determined by availability..."
}
```

## Circuit breaker

Per-provider circuit breaker prevents repeated calls to failing providers:

```
CLOSED (normal)
   │
   └── 3 failures in 60s
       │
       ▼
   OPEN (reject all calls for 60s)
       │
       └── timeout expires
           │
           ▼
   HALF-OPEN (try one call)
       │
       ├── Success → CLOSED
       └── Failure → OPEN (reset timer)
```

## Provider selection criteria

1. **User config**: `model_provider` setting in `settings.toml`
2. **API key presence**: Provider must have credentials
3. **Provider validation**: `validate()` checks endpoint reachability
4. **Task type**: Some providers preferred for specific operations

## Fallback chain behavior

```
Request (model_provider = "auto")
  │
  ├── Try openai
  │     ├── Success → done
  │     └── Fail → next
  │
  ├── Try gemini
  │     ├── Success → done
  │     └── Fail → next
  │
  ├── ... (anthropic, groq, together, ollama, lmstudio, cloud)
  │
  └── Try noop (always succeeds, offline fallback)
```

## Provider health

The `health` command checks all configured providers:

```bash
siyarix health
```

Output includes provider status (available/unavailable), latency, and error counts.

## Retry strategy

```python
# tenacity-based retry
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(TransientError)
)
```

Transient errors (timeouts, connection resets, 429s) are retried. Permanent errors (auth failures, invalid requests) immediately fail.
