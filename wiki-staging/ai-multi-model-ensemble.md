# 🧠 Multi-Model Ensemble

> [!NOTE]
> 👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Ever wish you could ask a panel of experts a question and go with the majority opinion? That's exactly what the `ProviderManager.ensemble_decide()` method does! 

By running a single query across multiple AI providers simultaneously, this method returns the **majority-vote result**. This approach gives your application three large superpowers:
- **Hallucination Resistance:** Catches when one AI model goes completely off the rails.
- **Consensus Validation:** Builds confidence when multiple top-tier models agree.
- **Graceful Degradation:** Keeps your app running smoothly even if an individual provider fails or times out.

> [!NOTE]
> Currently, this is a lightweight, functional implementation embedded directly in `ProviderManager` rather than a standalone class. We have an exciting roadmap for a more feature-rich ensemble, including weighted voting strategies and advanced hallucination scoring!

---

## 🏗️ Architecture

Here is a high-level look at how a user task flows through the ensemble:

```text
User Task
    │
    ▼
┌──────────────────────────────────────────────┐
│       ProviderManager.ensemble_decide()      │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │  OpenAI  │  │  Gemini  │  │ Anthropic  │  │
│  │(gpt-4o)  │  │(gemini)  │  │ (claude)   │  │
│  └────┬─────┘  └────┬─────┘  └──────┬─────┘  │
│       │             │               │        │
│       ▼             ▼               ▼        │
│  ┌────────────────────────────────────────┐  │
│  │        Majority Vote (Counter)         │  │
│  └────────────────────────────────────────┘  │
│                      │                       │
│                      ▼                       │
│              Selected Response               │
└──────────────────────────────────────────────┘
```

---

## ⚙️ How It Works

Behind the scenes, we use asynchronous Python to make this process incredibly fast and robust. Here is the magic signature:

```python
async def ensemble_decide(
    self, system_prompt: str, user_prompt: str, providers: list[str]
) -> str:
```

### The 5-Step Process
1. **Concurrent Execution:** Every provider in your list is called at the exact same time using `asyncio.gather`.
2. **Fault Tolerance:** If one provider crashes, it doesn't bring down the ship. Errors are caught and ignored.
3. **Data Extraction:** The system normalizes responses, pulling out the core text whether the API returns a dictionary, an object, or a raw string.
4. **Tallying the Votes:** A classic Python `collections.Counter` finds the most common response.
5. **Declaring a Winner:** The majority response is returned. 

> [!WARNING]
> If *all* providers fail to return a valid response, the method will raise a `RuntimeError`. Always ensure you have reliable fallback providers in your list!

Here is the core logic in action:

```python
# 1 & 2: Call all providers concurrently, ignoring individual failures
responses = await asyncio.gather(
    *[self.complete(p, self.select_provider(p)[1], system_prompt, user_prompt) for p in providers],
    return_exceptions=True,
)

# 3: Extract valid text content
valid = []
for r in responses:
    if isinstance(r, Exception):
        continue
    if isinstance(r, dict) and "content" in r:
        valid.append(r["content"])
    elif hasattr(r, "content"):
        valid.append(r.content)
    elif isinstance(r, str):
        valid.append(r)

# Guard against total failure
if not valid:
    raise RuntimeError("All ensemble providers failed")

# 4 & 5: Find and return the most common answer
most_common = Counter(valid).most_common(1)[0][0]
return most_common
```

---

## 🗳️ Voting Strategy

Right now, we use a straightforward **majority vote** (plurality) system. Whichever response text occurs most frequently across your selected providers is declared the winner. 

Because AI ensemble decision-making is an emerging field, we've focused heavily on creating a reliable, reliable foundation:

| Aspect | Behavior |
|--------|----------|
| **Strategy** | Majority (plurality) — the most common identical response wins. |
| **Speed** | Maximum efficiency! All providers are queried concurrently. |
| **Resilience** | Individual API timeouts or errors are completely absorbed. |
| **Flexibility** | Automatically parses `dict`, `object`, and plain string response formats. |

---

## 🎯 Selecting Providers

You rarely want to hardcode your providers. Instead, use `ProviderManager.get_providers_by_capability()` to dynamically select the best models for the job based on what they can do:

```python
# Get all cloud providers that support function calling
providers = pm.get_providers_by_capability(
    function_calling=True,
    local=False,
    free=False,
)

# On a budget? Get only free-tier providers!
free_providers = pm.get_providers_by_capability(free=True)
```

### Capability Filters

| Parameter | What it filters for |
|-----------|---------------------|
| `vision` | Providers that can "see" and process image inputs. |
| `free` | Models where the cost tier is explicitly set to `FREE`. |
| `local` | Privacy-first models running locally on your machine. |
| `function_calling` | Providers capable of executing tools and structured functions. |

> [!TIP]
> Mixing local and cloud providers is a great way to maintain high availability while managing costs!

---

## 🚀 Usage Example

Ready to put it to the test? Here is a complete example of how to use the ensemble in your code:

```python
from siyarix.providers import ProviderManager

pm = ProviderManager.get_instance()

# Hand-pick your dream team
providers = ["openai", "gemini", "anthropic"]

result = await pm.ensemble_decide(
    system_prompt="You are a senior security analyst.",
    user_prompt="What ports are typically open on a standard web server?",
    providers=providers,
)

print(f"Ensemble consensus: {result}")
```

### 💬 Chat Engine Integration

The ensemble concept isn't just for raw API calls. The chat engine (`chat/engine.py`) uses a lightweight `MultiModelEnsemble` stub to bring this power directly to user conversations. It applies a weighted voting strategy and gives you a neat little consensus dashboard:

```text
┌──────────────────────────────────────────────┐
│ 🔮 Multi-Model Ensemble                      │
│                                              │
│ Ensemble: Weighted consensus across 3 models │
│ Providers: openai, gemini, anthropic         │
│ Consensus: 67%  Hallucination risk: 33%      │
└──────────────────────────────────────────────┘
```

---

## 🕵️ Hallucination Detection (Emerging Feature)

One of the coolest things about querying multiple models is that you can mathematically detect when an AI is "hallucinating" (making things up). We do this by measuring the variance between their answers:

- **Low Variance:** Everyone agrees. You can trust this answer. (Low Hallucination Risk)
- **High Variance:** The models are giving wildly different answers. Flag this for human review! (High Hallucination Risk)

Our `EnsembleResult` dataclass tracks all of this metadata for you:

```python
@dataclass
class EnsembleResult:
    task: str
    responses: list[dict]         # Every provider's raw answer
    selected_plan: str            # The winning response
    voting_strategy: str          # e.g., 'majority', 'weighted'
    consensus_level: float        # Score from 0.0 to 1.0
    hallucination_risk: float     # Score from 0.0 to 1.0 (Higher = bad)
    total_cost: float             # Cumulative cost of all API calls
    total_latency_ms: float       # Total wall-clock time
```

---

## 💰 Cost Tiers

Running queries across multiple providers means costs can add up quickly. Thankfully, the `UsageTracker` monitors everything per-call based on our defined tiers:

> [!CAUTION]
> Remember that an ensemble multiplies your API costs by the number of paid providers you include. Use `FREE` and `LOW` tier providers strategically!

| Cost Tier | Rate (per output token) | Example Providers |
|-----------|------------------------|-------------------|
| `FREE` | $0.000000 | Ollama, LM Studio, llama.cpp |
| `LOW` | $0.00000015 | Groq, Perplexity, Cerebras |
| `MEDIUM` | $0.000002 | OpenAI, Together, OpenRouter |
| `HIGH` | $0.00001 | Anthropic (certain premium models) |

*Internal rate card implementation:*
```python
rates = {
    CostTier.FREE: 0.0,
    CostTier.LOW: 0.15e-6,
    CostTier.MEDIUM: 2.0e-6,
    CostTier.HIGH: 10.0e-6,
}
```

---

## 🔗 Related Modules

Want to dive deeper into the codebase? Check out these related files:

| Module | Location | What it does |
|--------|----------|--------------|
| **`ProviderManager.ensemble_decide`** | `src/siyarix/providers/manager.py:302` | The core production ensemble logic. |
| **`ProviderManager.get_providers_by_capability`**| `src/siyarix/providers/manager.py:240` | Helper for filtering and selecting providers. |
| **`UsageTracker`** | `src/siyarix/providers/usage.py` | Calculates and tracks your token costs. |
| **`ProviderProfile`** | `src/siyarix/providers/types.py` | Metadata and capability flags for each AI. |
| **`MultiModelEnsemble`** | `src/siyarix/chat/stubs.py` | UI/Chat integration for displaying consensus. |
