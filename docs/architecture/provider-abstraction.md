# 🧩 Provider Abstraction Layer

!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. Some of the architectural components and features described on this page might currently be **Planned, Work in Progress, or basic implementations**. Stay tuned as it evolves! 🚀


Welcome to the **Provider Abstraction Layer**! This component is the beating heart of our AI infrastructure. It smoothly decouples all AI-dependent components from specific model backends, making our system resilient, flexible, and fully provider-agnostic.

Think of it as an intelligent traffic controller for your AI models. It effortlessly manages **26 different provider profiles** with features like automatic failover, circuit breaking, exponential backoff, and token usage tracking. Plus, it brings everything together under a single, unified `OpenAICompat` adapter.

!!! note
    Provider states are intelligently persisted as JSON files. This ensures your AI configuration and cooldown statuses carry over seamlessly across different sessions!

---

## 🏗️ Architecture Overview

Here is a bird's-eye view of how the abstraction layer sits within the overall system:

```text
┌──────────────────────────────────────────────────────┐
│                Consumer Layer                        │
│  (Planner, ChatSession, AutonomousExecutor, Swarm)   │
└─────────────────────────┬────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────┐
│                   ProviderManager                    │
│                                                      │
│  • Provider selection (preference chain + scoring)   │
│  • Failover orchestration                            │
│  • Circuit breaking (record_failure)                 │
│  • Rate limiting                                     │
│  • DLP data redaction                                │
│  • Provider filtering by capability                  │
└──────┬───────────┬───────────┬───────────┬───────────┘
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

!!! tip
    `*` **The `OpenAICompat` adapter** (`siyarix/chat/openai_compat.py`) acts as a universal translator. It provides a standardized OpenAI-compatible API across *all* providers that support the OpenAI chat completions protocol!

---

## 🔌 The Provider Interface

Unlike traditional object-oriented systems that use heavy abstract base classes, we define providers using lightweight data profiles. This makes them incredibly fast to load and easy to configure.

You can find the core data models in the types module (`siyarix/providers/types.py`):

```python
@dataclass
class ProviderProfile:
    name: str
    display_name: str
    provider_type: str           # "cloud" | "local" | "heuristic"
    base_url: str
    api_key_env: str | None      # Which environment variable holds the key?
    models: list[ModelInfo]
    capabilities: set[str]       # e.g., "chat", "embed", "function_calling", "vision"
    priority: int                # Position in the preference chain
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
    capabilities: set[str]       # What can this model do?
```

### 🎯 Provider Selection

Need a provider with specific superpowers? Filtering is built right in:

```python
# Grab providers with the exact capabilities you need:
vision_providers = pm.get_providers_by_capability("vision")
free_providers = pm.get_providers_by_capability("free")
local_providers = pm.get_providers_by_capability("local")
fn_call_providers = pm.get_providers_by_capability("function_calling")
```

---

## 🌐 The 26 Provider Profiles

Our system is ready out-of-the-box to connect with an impressive array of AI backends.

### ☁️ Cloud Providers (API Key Required)

These providers require authentication but offer the most powerful, cutting-edge models.

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
| `azure` | `openai` | Azure OpenAI (personal, managed AD) |
| `opencode_zen` | `openai` | OpenCode Zen backend |

### 💻 Local Providers (No API Key Required)

Run AI completely offline, free, and secure directly on your own hardware!

| Registry Name | Default Endpoint | Notes |
|--------------|-----------------|-------|
| `ollama` | `http://localhost:11434` | The easiest way to pull and run open-weight models |
| `lmstudio` | `http://localhost:1234` | Awesome GUI + local API server |
| `llamacpp` | `http://localhost:8080` | Highly efficient CPU/GPU inference |
| `vllm` | Configurable | Built for high-throughput GPU serving |
| `localai` | `http://localhost:8080` | A seamless drop-in OpenAI replacement |

### 🛠️ Heuristic Fallback

When all else fails, we have reliable, non-AI fallbacks.

| Name | Description |
|------|-------------|
| `registry` | RegistryPlanner — A 100% rule-based system, always available and offline-safe. |

---

## 🤝 OpenAICompat Adapter

Dealing with dozens of different API specifications is a headache. That's why we created the `OpenAICompat` adapter (`siyarix/chat/openai_compat.py`). It acts as a universal bridge for over 14+ providers.

By standardizing around the OpenAI chat completions protocol, you write your code *once*, and it automatically supports:
- 💬 Chat completions & Streaming responses
- 🧠 Embedding generation
- ⚙️ Tool and function calling
- 📋 Structured output (JSON mode)

```python
# Look how easy it is to swap providers!
adapter = OpenAICompat(provider="openai", api_key=...)
adapter = OpenAICompat(provider="groq", api_key=...)
adapter = OpenAICompat(provider="deepseek", api_key=...)
```

---

## 🧠 ProviderManager

The `ProviderManager` (`siyarix/providers/manager.py`) is the smart coordinator of the entire system.

### 🚦 Selection Logic

How does it decide which AI to use? It evaluates several factors dynamically:
1. **User Preference**: Starts with your `model_provider` config.
2. **Key Availability**: Checks the `CredentialStore` for valid API keys.
3. **Health Status**: Performs quick connectivity tests.
4. **Task Matching**: Ensures the provider supports the requested feature (like vision or function calling).
5. **Cooldowns**: Actively avoids providers that recently failed.
6. **Historical Reliability**: Deprioritizes providers with high error rates.

### ⛓️ The Preference Chain

When set to `model_provider = "auto"`, the system acts autonomously, marching down a prioritized list until it finds a working model:

> Gemini → OpenAI → Anthropic → Groq → Together → OpenRouter → DeepSeek → xAI → Mistral → Perplexity → Cerebras → Fireworks → ZAI → MiniMax → Moonshot → NVIDIA → HuggingFace → Azure → OpenCode Zen → Ollama → LM Studio → llama.cpp → vLLM → LocalAI → Registry (Heuristic)

### 🔄 Failover Behavior

!!! info
    Our architecture guarantees robust failovers. If an AI provider goes down, your app doesn't crash—it seamlessly routes to the next best option!

```text
Request → Provider A (Preferred)
              │
              ├── ✅ Success → Return result, record success
              │
              └── ❌ Failure → Trigger record_failure()
                            │
                            ▼
                    ProviderStateManager enforces cooldown
                            │
                            ▼
                    Provider B (Next in chain)
                            │
                            ├── ✅ Success → Return result
                            │
                            └── ❌ Failure → Continue chain
                                          │
                                          ▼
                                  Registry (Heuristic fallback)
```

### 📊 Live Statistics

Want to know how your providers are performing?

```python
stats = provider_manager.stats()
# You instantly get detailed usage stats, error rates, and current statuses!
```

---

## ⚡ Circuit Breaking

To protect your system from hanging endlessly on broken APIs, we use a **Circuit Breaker** pattern via `ProviderManager.record_failure()`.

| Parameter | Default | What it means |
|-----------|---------|---------------|
| **Failure threshold** | 3 | How many consecutive errors trigger a circuit "trip" (opening the circuit). |
| **Recovery timeout** | 60s | Time to wait before cautiously trying the provider again (half-open). |
| **Cooldown duration** | 300s | Total time a provider is "benched" after failing hard. |

```python
state = provider_manager.record_failure("openai")  # Trips to OPEN after 3 strikes
state = provider_manager.record_success("gemini")  # Restores trust, moving back to CLOSED
```

---

## 💾 ProviderStateManager

Your system's memory isn't wiped when you restart. The `ProviderStateManager` saves the exact state of your providers into a simple JSON file (`provider_state.json`).

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

!!! tip
    Because this is saved to disk, if a provider hits a rate limit right before you close your app, it will *still* correctly skip that provider when you reboot!

---

## 📈 UsageTracker

Keep your AI costs under control! The `UsageTracker` monitors every single token and penny.

| Metric | How it's tracked |
|--------|------------------|
| **Prompt tokens** | Per Request |
| **Completion tokens** | Per Response |
| **Total tokens** | Request + Response |
| **Estimated cost** | Based on the provider's specific rate card |
| **Request count** | Per Session |
| **Latency** | Per Request |

```python
tracker = UsageTracker()
tracker.record("openai", prompt_tokens=150, completion_tokens=450, latency=2.3)
summary = tracker.get_summary("openai")
# Instantly see exactly what you spent:
# UsageSummary(total_tokens=600, total_cost=0.009, avg_latency=2.3, request_count=1)
```

---

## ⏱️ Exponential Backoff

When an API blinks with a temporary error (like a 429 Rate Limit or 503 Server Error), we don't just hammer it. We respectfully back off using jittered exponential delays:

```python
# Formula for our smart delays
backoff = min(2 ** attempt + random.uniform(0, JITTER), MAX_DELAY)
```

| Attempt | Delay Range | Max Delay |
|---------|-------------|-----------|
| 1st Try | 1.0 – 2.0s | 30s |
| 2nd Try | 2.0 – 3.0s | 30s |
| 3rd Try | 4.0 – 5.0s | 30s |
| 4th Try | 8.0 – 9.0s | 30s |
| 5th+ Try | 16.0 – 17.0s | 30s |

---

## 🦙 Ollama Utilities

Running models locally? `siyarix/providers/ollama_utils.py` makes it a breeze with dedicated helpers for Ollama:

- 🔍 **Auto-Discovery:** Automatically lists your downloaded models.
- ⬇️ **Smart Pulling:** Downloads missing models with live progress tracking.
- ❤️ **Health Checks:** Monitors your local endpoint's vitals.
- 💻 **Hardware Awareness:** Intelligently selects models that fit your specific GPU/CPU constraints.

---

## 🛡️ Security & Data Masking (DLP)

We take your data seriously. Before *any* information leaves your machine and hits a cloud provider, our `DLPEngine` (`siyarix/dlp.py`) scrubs it clean.

!!! warning
    Never disable the DLPEngine in a production cloud environment!

| Data Type | Sent to Cloud Provider | Behavior for Local Models |
|-----------|------------------------|---------------------------|
| **IP addresses** | Masked as `10.x.x.x` | Sent safely unmasked |
| **Credentials** | `[REDACTED]` | Permanently redacted |
| **API keys** | `[REDACTED]` | Permanently redacted |
| **Internal hostnames** | Masked as `example.com` | Sent safely unmasked |
| **JWTs / tokens** | `[REDACTED]` | Permanently redacted |

---

## 🏷️ ModelAliases

AI companies change their model names all the time. The `ModelAliases` system (`siyarix/model_aliases.py`) abstracts this away so your code never breaks when a new version drops!

| Your Code Asks For | We Actually Route To |
|--------------------|----------------------|
| `gpt-4` | `gpt-4-turbo` or `gpt-4o` (automatically uses the best available) |
| `claude-3` | `claude-3-opus` or `claude-3-sonnet` |
| `gemini-pro` | `gemini-1.5-pro` or `gemini-2.0-flash` |
| `llama-3` | `llama-3-70b` or `llama-3-8b` |
| `mixtral` | `mixtral-8x7b` or `mixtral-8x22b` |

---

## 🗺️ Component Relationships Map

Here is how all these incredible features tie together:

```text
                   ┌────────────────────────┐
                   │     Consumer Layer     │
                   │  (Planner, Chat, etc.) │
                   └────────┬───────────────┘
                            │
                            ▼
                   ┌────────────────────────┐
                   │    ProviderManager     │
                   │                        │
                   │  ┌──────────────────┐  │
                   │  │ ⛓️ Pref. Chain    │  │
                   │  │  + Failover      │  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │ ⚡ Circuit Break  │  │
                   │  │  (record_failure)│  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │ ⏱️ Exp. Backoff   │  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │ 🛡️ DLP Redaction  │  │
                   │  └──────────────────┘  │
                   │  ┌──────────────────┐  │
                   │  │ 🎯 Capability     │  │
                   │  │    Filtering     │  │
                   │  └──────────────────┘  │
                   └────────┬───────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ OpenAICompat │ │ ProviderState│ │ Ollama       │
    │ Adapter      │ │ Manager      │ │ Utils        │
    │ (14+ APIs)   │ │ (JSON File)  │ │ (Local AI)   │
    └──────────────┘ └──────────────┘ └──────────────┘
                            │
                            ▼
                   ┌────────────────────────┐
                   │     UsageTracker       │
                   │  (Tokens + Cost Per    │
                   │   Provider)            │
                   └────────────────────────┘
```
