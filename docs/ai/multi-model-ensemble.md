# Multi-Model Ensemble

The `MultiModelEnsemble` runs parallel AI queries across multiple providers and aggregates results using configurable voting strategies.

## Architecture

```
User Task
    │
    ▼
┌─────────────────────────────────────────┐
│          MultiModelEnsemble             │
│                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────┐  │
│  │  OpenAI  │  │  Gemini  │  │Ollama│  │  ...
│  │ (gpt-4o) │  │(1.5-pro) │  │(3.1) │  │
│  └────┬─────┘  └────┬─────┘  └──┬───┘  │
│       │             │           │       │
│       ▼             ▼           ▼       │
│  ┌──────────────────────────────────┐   │
│  │       Voting Aggregator         │   │
│  │  (majority/consensus/weighted/  │   │
│  │   best_score)                   │   │
│  └──────────────┬───────────────────┘   │
│                 ▼                       │
│         Selected Plan                  │
└─────────────────────────────────────────┘
```

## Voting strategies

| Strategy | How it works | Best for |
|----------|-------------|----------|
| `MAJORITY` | Picks the most common plan across providers | General consensus |
| `CONSENSUS` | Requires all providers to agree | High-stakes decisions |
| `WEIGHTED` | Weighted by provider confidence scores | Balanced accuracy |
| `BEST_SCORE` | Selects the highest-confidence response | Maximum quality |

## Complexity tiers

Tasks are routed to providers based on complexity:

| Tier | Providers | Use case |
|------|-----------|----------|
| `simple` | Ollama, Groq | Fast, low-cost queries |
| `medium` | Gemini, Together | Standard planning |
| `complex` | OpenAI | Advanced reasoning, critical tasks |

## Provider costs

Cost tracking for budget-aware routing:

| Provider | Cost per 1K tokens |
|----------|-------------------|
| OpenAI | $0.010 |
| Gemini | $0.0025 |
| Ollama | $0.000 (local) |
| Groq | $0.005 |
| Together | $0.006 |

## Usage

```python
from siyarix.multi_model_ensemble import MultiModelEnsemble, VotingStrategy

ensemble = MultiModelEnsemble()
ensemble.register_provider("openai", openai_provider)
ensemble.register_provider("gemini", gemini_provider)
ensemble.register_provider("ollama", ollama_provider)

result = await ensemble.execute(
    task="scan 10.0.0.1 for vulnerabilities",
    strategy=VotingStrategy.WEIGHTED,
    tier="complex"
)

print(f"Selected plan: {result.selected_plan}")
print(f"Consensus level: {result.consensus_level}")
print(f"Hallucination risk: {result.hallucination_risk}")
print(f"Total cost: ${result.total_cost:.4f}")
```

## Hallucination detection

The ensemble detects potential hallucinations by measuring confidence variance across providers:

- **Low variance**: High agreement → low hallucination risk
- **High variance**: Disagreement → high hallucination risk
- Risk score is included in `EnsembleResult.hallucination_risk`

## Response data model

```python
@dataclass
class EnsembleResult:
    task: str
    responses: list[ModelResponse]     # All provider responses
    selected_plan: str                 # Winning plan
    selection_reason: str              # Why this plan was chosen
    voting_strategy: VotingStrategy
    consensus_level: float             # 0.0 to 1.0
    hallucination_risk: float          # 0.0 to 1.0
    total_cost: float                  # Cumulative cost
    total_latency_ms: float            # Time for all providers
```
