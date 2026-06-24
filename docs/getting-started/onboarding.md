# Onboarding Wizard

Siyarix includes an interactive 11-step wizard (steps 0-10) that configures providers, themes, security defaults, and notifications on first launch. The wizard is designed to be warm, guided, and thorough — it detects your environment, recommends optimal settings, and sets up your workspace with minimal friction.

## Launching the Wizard

```bash
siyarix                    # Auto-starts if not initialized
siyarix init               # Manual start
siyarix init --force       # Re-run even if configured
```

## The 11 Steps (0-10)

| Step | Action | Purpose |
|------|--------|---------|
| 0 | Welcome & Ethics Pledge | Acceptable use acknowledgment — you must accept the ethical use pledge to continue |
| 1 | Platform Detection | Detects OS, architecture, hardware specs, shell, package managers, GPU, RAM, and environment type (desktop/headless/WSL/container) |
| 2 | Requirements Check | Verifies Python 3.12+, pip, git, curl, writable config directory |
| 3 | Dependencies & SDKs | Installs core Python packages (pydantic, rich, httpx, cryptography, prompt_toolkit, pyyaml, jinja2, openai, etc.) |
| 4 | Tool Discovery | Scans PATH for cybersecurity tools — installs missing ones via ToolInstaller |
| 5 | Credential Vault | Initializes the AES-256-GCM encrypted credential store via CredentialStore |
| 6 | Provider Configuration | Recommended (auto-detect + local provider), online (cloud API), offline (local), custom, or skip |
| 7 | Mode Selection | Choose execution mode: integrated (default), autonomous, or registry-only |
| 8 | Persona & System Message | Select security mindset (auto, redteam, blueteam, dfir, appsec, etc.) and optional custom system prompt |
| 9 | Preferences | Theme, output format, stealth mode, notifications, log level, history retention |
| 10 | Network Diagnostics | Tests internet connectivity, DNS resolution, provider API connectivity |
| 11 | Finalize & Learning Setup | Runs health check, migrates .env if present, sets up shell completions, configures PATH, initializes the learning system |

## AI Provider Selection (Step 6)

**Cloud providers**: OpenAI, Anthropic, Google Gemini, Groq, Together AI, DeepSeek, xAI (Grok), Mistral, Perplexity, OpenRouter, Cerebras, Fireworks AI, HuggingFace, Azure OpenAI, NVIDIA Nemotron, MiniMax, Moonshot, OpenCode Zen, Z.AI — require API keys.

**Local engines**: Ollama, LM Studio, llama.cpp, vLLM, LocalAI — run fully offline with no API key required. Recommended setup auto-detects and installs the best provider for your hardware.

**Recommended flow**: Siyarix analyzes available RAM and GPU to suggest an optimal cybersecurity model:

- **≤4 GB**: Lightweight (e.g., `IHA089/drana-infinity-3b`)
- **4-8 GB**: Balanced (e.g., `IHA089/drana-infinity-7b`)
- **8-16 GB**: Capable (e.g., `supergoatscriptguy/mythos-sec:8b`)
- **16+ GB**: High-end (e.g., `supergoatscriptguy/mythos-sec:24b`)

## Workspace Layout

```text
~/.siyarix/
├── personas/           # AI personality definitions
├── personas/custom/    # User-created custom personas
├── profiles/           # Provider profiles
├── memory/             # Knowledge graph persistence
├── logs/sessions/      # Session logs
├── logs/audit/         # Tamper-evident audit trail
├── cache/tool_outputs/ # Cached tool results
├── cache/ai_plans/     # AI plan cache
├── cache/dns/          # DNS resolution cache
├── cache/intel/        # Threat intelligence cache
├── cache/scan_results/ # Scan result cache
├── cache/user_data/    # User data cache
├── templates/reports/  # Custom report templates
├── templates/playbooks/# Playbook templates
├── playbooks/          # User playbooks
├── sessions/           # Saved sessions
├── masking/            # DLP masking state
├── achievements/       # Gamification data
└── settings.toml       # Central configuration
```

## Unattended / CI Setup

```bash
export MODEL_PROVIDER=openai
export OPENAI_API_KEY=sk-...
siyarix config set model_provider openai
siyarix auth set-key openai
```

## Next Steps

- [First Run](first-run.md) — Launch your first scan
- [CLI Commands Reference](../user/cli-commands.md) — Complete command manual
