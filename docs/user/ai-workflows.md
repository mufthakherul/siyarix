# 🤖 AI-Powered Workflows

Welcome to the future of security operations! Siyarix leverages cutting-edge AI providers to understand your natural language requests, select the right tools, and autonomously execute complex plans. Simply tell Siyarix what you want to do, and our execution engine will turn your intent into a structured, step-by-step plan.

---

## 🗣️ Natural Language Command Interpretation

Have you ever wanted to just *tell* your tools what to do? Now you can!

```bash
siyarix run "scan the network 10.0.0.0/24 for open ports and service versions"
```

> [!NOTE]
> Siyarix translates human language into security actions. You don't need to memorize complex flags or syntax anymore!

Behind the scenes, the execution engine processes your input through these steps:

1. **Intent Parsing**: Figures out your target, the necessary parameters, and what you actually want to achieve.
2. **Tool Selection**: Matches your request against the capabilities of tools available in the Siyarix registry.
3. **Plan Construction**: Builds a smart, organized execution plan (even handling parallel tasks!).
4. **Execution**: Runs the steps in the correct order.
5. **Result Aggregation**: Collects everything and presents you with neat, structured findings.

---

## 🎯 Goal-Driven Autonomous Agent

Want to tackle a massive task while you grab a coffee? Meet the autonomous agent.

```bash
siyarix agent "enumerate all subdomains, find live hosts, scan for vulns, and report"
```

The agent uses a smart "Observe-Reason-Act" loop to break down complex objectives into manageable steps.

### ⚙️ Agent Modes

| Mode | CLI Flag | What It Does |
|------|----------|-------------|
| **Registry** | `--mode offline` | Traditional planning using our tool registry (no AI needed). Great for air-gapped setups! |
| **Autonomous** | `--mode autonomous` | Full AI control! The agent plans and executes steps without asking for confirmation. |
| **Hybrid** | `--mode integrated` | The sweet spot. AI proposes the plans, but keeps you in the loop during execution. |

---

## 🛡️ Multi-Provider Failover

Don't worry about an AI outage stopping your work. Siyarix has your back!

If your primary AI provider goes down:
1. **Circuit Breaker**: Trips automatically after 3 failures in 60 seconds.
2. **Next Provider**: Siyarix smoothly switches to the next provider on your list.
3. **Registry Fallback**: If *all* AI providers are down, Siyarix falls back to its offline registry planner.
4. **Graceful Degradation**: You keep working! Commands still execute, just without the AI magic.

> [!TIP]
> You can easily configure your preferred backup order!
> ```bash
> siyarix config set provider_preference '["openai", "anthropic", "gemini"]'
> ```

---

## 🧠 Prompt Architecture

Ever wonder how the AI knows so much about your environment? We build rich prompts using:

- **System Context**: Details about your platform and available tools.
- **User Input**: What you typed (commands or plain English).
- **Conversation History**: Keeping track of what we've already discussed.
- **Safety Constraints**: Rules and permission gates to keep you safe.
- **Persona Instructions**: Adapting to your needs (e.g., acting as a red teamer or a blue teamer).

---

## 🛠️ Tool Selection

The AI doesn't just guess; it selects tools based on strict criteria:

1. **Capability**: Can the tool actually do the job?
2. **Availability**: Is it installed on your system?
3. **Platform**: Does it work on your OS (Windows, Mac, Linux)?
4. **Safety**: Is it appropriate for the current safety mode?

> [!IMPORTANT]
> The `ToolRegistry` keeps track of all discovered security tools on your system. It automatically scans your system path on startup, so you're always ready to go.

---

## 📊 Context Management

To keep the AI sharp and focused, we manage its memory (context window) carefully:

- **Smart Forgetting**: Old conversations are truncated so the AI doesn't get overwhelmed.
- **Summarization**: Verbose tool outputs are summarized to keep things concise.
- **Offline Storage**: Massive result sets are stored safely offline and referenced when needed.

---

## 🔌 Offline Operation

No internet? No AI? No problem! Siyarix is built to work perfectly offline.

When using `--mode offline` or if the AI is unreachable:
- The `RegistryPlanner` handles your commands using smart pattern matching.
- The `OfflineStore` provides rich, contextual responses.
- All your tools remain 100% usable.

---

## 🌐 Supported AI Providers

Siyarix plays nicely with all the major AI models. Here is how to configure them:

| Provider | Configuration Command |
|----------|-----------------------|
| **OpenAI** | `siyarix auth set-key openai --key sk-...` |
| **Anthropic** | `siyarix auth set-key anthropic --key sk-ant-...` |
| **Gemini** | `siyarix auth set-key gemini --key AIz...` |
| **Groq** | `siyarix auth set-key groq --key ...` |
| **Together** | `siyarix auth set-key together --key ...` |
| **OpenRouter** | `siyarix auth set-key openrouter --key ...` |
