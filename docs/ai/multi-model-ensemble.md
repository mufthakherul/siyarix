# Multi-Model Ensemble

The `ProviderManager.ensemble_decide()` method runs a query across multiple AI providers simultaneously and returns the majority-vote result. This provides hallucination resistance, consensus validation, and graceful degradation when individual providers produce unreliable output.

> **Note**: This is a lighter-weight implementation than a full `MultiModelEnsemble` class. The `ProviderManager.ensemble_decide()` (in `src/siyarix/providers/manager.py:299`) is the production implementation. A more feature-rich `MultiModelEnsemble` stub exists for future expansion.

---

## Architecture

```
User Task
    │
    ▼
┌──────────────────────────────────────────────┐
│          ProviderManager.ensemble_decide()   │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │  OpenAI  │  │  Gemini  │  │  Anthropic  │ │
│  │ (gpt-5.5)│  │ (gemini) │  │ (claude)    │ │
│  └────┬─────┘  └────┬─────┘  └──────┬──────┘ │
│       │             │               │         │
│       ▼             ▼               ▼         │
│  ┌──────────────────────────────────────────┐ │
│  │       Majority Vote (Counter)            │ │
│  └──────────────────────────────────────────┘ │
│                      │                         │
│                      ▼                         │
│              Selected Response                │
└──────────────────────────────────────────────┘
```

---

## How It Works

```python
async def ensemble_decide(
    self, system_prompt: str, user_prompt: str, providers: list[str]
) -> str:
```

1. Each provider in the list is called concurrently via `asyncio.gather`
2. Responses are collected (with `return_exceptions=True` to tolerate individual failures)
3. Valid responses are extracted (supports dict, object, and string response formats)
4. `collections.Counter` determines the most common response
5. The majority response is returned; raises `RuntimeError` if all providers fail

```python
responses = await asyncio.gather(
    *[self.complete(p, model, system_prompt, user_prompt) for p in providers],
    return_exceptions=True,
)

valid = [r["content"] for r in responses if isinstance(r, dict) and "content" in r]
most_common = Counter(valid).most_common(1)[0][0]
```

---

## Voting Strategy

The current implementation uses **majority vote** (plurality). The most frequently occurring response text across all providers is selected.

Planned strategies (for future `MultiModelEnsemble`):

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| `MAJORITY` | Most common response across providers | General consensus |
| `CONSENSUS` | Requires unanimous agreement | High-stakes decisions |
| `WEIGHTED` | Weighted by provider confidence/priority | Balanced accuracy |
| `BEST_SCORE` | Highest-confidence response selected | Maximum quality |

---

## Provider Selection for Ensemble

Use `ProviderManager.get_providers_by_capability()` to select ensemble participants:

```python
# Get all cloud providers that support function calling
providers = pm.get_providers_by_capability(
    function_calling=True,
    free=False,
)

# Get only free-tier providers
free_providers = pm.get_providers_by_capability(free=True)
```

### Capability Filters

| Parameter | Filters By |
|-----------|-----------|
| `vision` | Providers supporting vision inputs |
| `free` | Cost tier is `FREE` |
| `local` | Provider type is `LOCAL` |
| `function_calling` | Supports tool/function calling |

---

## Cost Tiers

Provider cost is tracked per-call via `UsageTracker`:

| Cost Tier | Rate (per output token) | Example Providers |
|-----------|------------------------|-------------------|
| `FREE` | $0.000000 | Ollama, LM Studio, llama.cpp |
| `LOW` | $0.00000015 | Groq, Perplexity, Cerebras |
| `MEDIUM` | $0.000002 | OpenAI, Together, OpenRouter |
| `HIGH` | $0.00001 | Anthropic (certain models) |

```python
rates = {
    CostTier.FREE: 0.0,
    CostTier.LOW: 0.15e-6,
    CostTier.MEDIUM: 2.0e-6,
    CostTier.HIGH: 10.0e-6,
}
```

---

## Usage Example

```python
from siyarix.providers import ProviderManager

pm = ProviderManager.get_instance()

# Select providers for ensemble
providers = ["openai", "gemini", "anthropic"]

result = await pm.ensemble_decide(
    system_prompt="You are a security analyst.",
    user_prompt="What ports are typically open on a web server?",
    providers=providers,
)

print(f"Ensemble decision: {result}")
```

---

## Hallucination Detection (Planned)

The ensemble framework is designed to detect potential hallucinations by measuring response variance:

- **Low variance**: High agreement across providers → low hallucination risk
- **High variance**: Disagreement → potential hallucination, flag for review

This is tracked in the planned `EnsembleResult` data model:

```python
@dataclass
class EnsembleResult:
    task: str
    responses: list[dict]         # All provider responses
    selected_plan: str            # Winning plan
    voting_strategy: str
    consensus_level: float        # 0.0 to 1.0
    hallucination_risk: float     # 0.0 to 1.0
    total_cost: float             # Cumulative cost
    total_latency_ms: float       # Wall-clock time
```

---

## Related Modules

| Module | Path | Purpose |
|--------|------|---------|
| `ProviderManager.ensemble_decide` | `src/siyarix/providers/manager.py:299` | Production ensemble implementation |
| `ProviderManager.get_providers_by_capability` | `src/siyarix/providers/manager.py:239` | Filter providers by capability flags |
| `UsageTracker` | `src/siyarix/providers/usage.py` | Token and cost tracking per provider/model |
| `ProviderProfile` | `src/siyarix/providers/types.py` | Provider metadata with capability flags |
