# Configuring AI Models

Siyarix relies on Large Language Models (LLMs) to act as its "Task Planner." Without a model, Siyarix can still run direct commands, but it won't be able to autonomously orchestrate complex multi-step plans.

We support several major providers out of the box.

---

## ☁️ Cloud Providers

If you want the smartest, most capable agent experience, we highly recommend using a top-tier cloud model.

### Google Gemini (Recommended)
Gemini 1.5 Pro and Gemini 1.5 Flash are exceptionally good at understanding JSON and shell commands.
1. Get an API key from Google AI Studio.
2. In the Siyarix chat, type:
   ```text
   /key set gemini <your-api-key>
   ```
3. Set the active model:
   ```text
   /model gemini
   ```

### OpenAI
GPT-4o and GPT-4-turbo are also heavily tested and work flawlessly.
1. Get an API key from the OpenAI Developer Platform.
2. In the Siyarix chat, type:
   ```text
   /key set openai <your-api-key>
   ```
3. Set the active model:
   ```text
   /model openai
   ```

### Anthropic
Claude 3.5 Sonnet is excellent for logical reasoning and bash script generation.
1. Get an API key from the Anthropic Console.
2. In the Siyarix chat, type:
   ```text
   /key set anthropic <your-api-key>
   ```
3. Set the active model:
   ```text
   /model anthropic
   ```

---

## 🦙 Local Models (Ollama)

If you are working on a sensitive assessment, air-gapped network, or simply don't want to send your prompt data to the cloud, Siyarix fully supports local, open-weights models via [Ollama](https://ollama.com/).

### Setting Up Ollama

1. **Install Ollama**: Download and install it from their official website.
2. **Pull a Model**: For security task planning, you need a model that is smart enough to generate valid JSON and understand bash syntax. We recommend `llama3` or `mistral`.
   ```bash
   ollama pull llama3
   ollama pull mistral
   ```
3. **Start the Ollama Server**: Ensure the background service is running on `http://localhost:11434`.

### Connecting Siyarix to Ollama

1. Open the Siyarix interactive shell.
2. Switch the active model provider to Ollama:
   ```text
   /model ollama
   ```
3. *(Optional)* By default, Siyarix will try to use the `llama3` model. If you want to use a specific model you downloaded (e.g., `mistral`), you can configure the specific model name in your `~/.siyarix/settings.toml`.

**Note on Local Models**: Local models are incredibly cool for privacy, but they are generally much smaller than cloud models like GPT-4o. You may notice that local models occasionally struggle to output perfectly formatted JSON or understand highly complex multi-tool plans. If this happens, try breaking your request into smaller, simpler steps!
