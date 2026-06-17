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

## Provider Profiles (24 total)

### Cloud Providers

| Registry name | SDK / API | Models |
|--------------|-----------|--------|
| `openai` | `openai` | GPT-4o, GPT-4, GPT-3.5-turbo |
| `gemini` | `google-generativeai` | Gemini 2.0 Flash, 1.5 Pro |
| `anthropic` | `anthropic` | Claude 3.5 Sonnet, Claude 3 Opus |
| `groq` | `groq` | Llama 3 70B, Mixtral 8x7B |
| `together` | `together` | Mixtral, DeepSeek, Llama |
| `openrouter` | `openai` | Multi-model router |
| `deepseek` | `openai` | DeepSeek-V2, DeepSeek-Coder |
| `xai` | `openai` | Grok |
| `mistral` | `mistralai` | Mistral Large, Small |
| `perplexity` | `openai` | Sonar, Sonar-Pro |
| `cerebras` | `openai` | Fast inference models |
| `fireworks` | `openai` | Open model serving |
| `zai` | `openai` | Z.AI models |
| `minimax` | `openai` | MiniMax models |
| `moonshot` | `openai` | Moonshot / Kimi |
| `nvidia` | `openai` | NVIDIA Nemotron |
| `huggingface` | `huggingface-hub` | Hugging Face Inference API |
| `azure` | `openai` | Azure OpenAI (enterprise) |
| `opencode_go` | `openai` | OpenCode Go |

### Local Providers (no API key needed)

| Registry name | Endpoint | Notes |
|--------------|----------|-------|
| `ollama` | `http://localhost:11434` | Pull any open-weight model |
| `lmstudio` | `http://localhost:1234` | GUI + API server |
| `llamacpp` | `http://localhost:8080` | Efficient CPU inference |
| `vllm` | Configurable | High-throughput GPU serving |
| `localai` | `http://localhost:8080` | Drop-in OpenAI replacement |

### Fallback

| Registry name | Description |
|--------------|-------------|
| `registry` | Heuristic/offline planner — no AI needed |

## Preference chains

Each provider type has a fallback chain. When the primary is unavailable, the system falls through to the next in order:

```
gemini → openai → anthropic → groq → together → openrouter → deepseek → xai →
mistral → perplexity → cerebras → fireworks → zai → minimax → moonshot →
nvidia → huggingface → azure → opencode_go → ollama → lmstudio → llamacpp →
vllm → localai → registry (heuristic)
```

When `model_provider = "auto"`, the system scans all configured providers in priority order, skipping any that were disabled this session due to rate-limit/auth errors. Providers are tried one at a time until one responds successfully or all are exhausted.

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

Five local providers require no API key:

- **Ollama**: `ollama pull llama3.1 && ollama serve` — port 11434
- **LM Studio**: Start app, enable API server — port 1234
- **llama.cpp**: `./server -m model.gguf` — port 8080
- **vLLM**: `vllm serve model` — configurable port
- **LocalAI**: `local-ai run` — port 8080

The **registry** provider is always available as heuristic fallback with no external dependencies.
