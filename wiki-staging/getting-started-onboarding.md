# 🪄 The Onboarding Wizard

Welcome to your first run with Siyarix!

We know that configuring security tools, managing API keys, and setting up environments can be a headache. That's exactly why we built the **Interactive Onboarding Wizard**.

On your very first launch, Siyarix will greet you with a warm, guided 11-step process. It automatically detects your system environment, recommends optimal settings based on your hardware, and sets up your entire workspace with virtually zero friction.

---

## 🚀 Launching the Wizard

Usually, you won't even need to think about this. If Siyarix detects that it hasn't been set up yet, the wizard starts automatically when you run the main command:

```bash
# Auto-starts if not initialized
siyarix

# Or, if you want to start it manually:
siyarix init

# Need to start fresh? Re-run the wizard from scratch:
siyarix init --force
```

---

## 🛤️ The 11 Steps of Onboarding

Curious about what the wizard actually does? Here is the complete breakdown of the 11 steps (Steps 0 to 10) it walks you through in under two minutes:

| Step | What Happens | Why We Do It |
|------|--------|---------|
| **0** | **Welcome & Ethics Pledge** | We ask you to acknowledge our acceptable use policy. You **must** accept the ethical use pledge to continue. Safety first! |
| **1** | **Platform Detection** | The wizard scans your OS, hardware specs, GPU, RAM, and shell to ensure Siyarix runs perfectly on your specific machine. |
| **2** | **Requirements Check** | Verifies you have Python 3.12+, `pip`, `git`, `curl`, and a writable configuration directory. |
| **3** | **Dependencies Check** | Ensures all core Python libraries (like `pydantic`, `rich`, `httpx`, and `cryptography`) are properly installed. |
| **4** | **Tool Discovery** | Siyarix scans your `PATH` for installed cybersecurity tools (like `nmap` or `nuclei`) and offers to install missing ones automatically! |
| **5** | **Credential Vault** | Initializes your ultra-secure AES-256-GCM encrypted credential store. |
| **6** | **AI Provider Configuration** | The brain! We help you select and configure your AI engine (Cloud APIs like OpenAI, or Local offline models like Ollama). |
| **7** | **Mode Selection** | Choose your default execution mode: Integrated (default), fully Autonomous, or Registry-only. |
| **8** | **Persona Setup** | Pick your default AI mindset (e.g., Red Team, Blue Team, AppSec) to frame how the AI approaches problems. |
| **9** | **Preferences** | Make it yours! Pick your terminal theme, output format, stealth mode toggles, and notification preferences. |
| **10** | **Diagnostics & Finalization** | Tests your internet connectivity, DNS, and API connections, then initializes your semantic learning system. You are ready to go! |

---

## 🧠 AI Provider Selection (Step 6 Deep Dive)

The most important step of the wizard is connecting Siyarix to its AI brain. You have two main paths:

### ☁️ Cloud Providers
Siyarix supports 25+ cloud AI APIs for maximum power and speed with zero local resource usage.

*Supported:* OpenAI (GPT-5/o-series), Anthropic (Claude Opus/Sonnet), Google Gemini (2.5/3.x), Groq, Together AI, DeepSeek, xAI (Grok 4), Mistral, OpenRouter, and many more.
*(Note: These require you to paste in your API key during setup).*

### 🏠 Local Offline Engines
Working in a sensitive environment? Run Siyarix **100% offline** with zero data leaving your machine!
*Supported:* Ollama (recommended), LM Studio, llama.cpp, vLLM, LocalAI.

**Hardware-Based Recommendations:**
The wizard analyzes your available RAM and GPU and recommends the best verified cybersecurity-focused model for your specific hardware:

---

#### ⚡ Ultra-Light (≤ 4 GB RAM)

| Model | Size | Ollama Pull Command | What it's for |
|-------|------|--------------------|----|
| **IHA089/drana-infinity-3b** ⭐ | 1.9 GB | `ollama pull IHA089/drana-infinity-3b` | Bug bounty, API testing, multi-step vuln chains — fast 3B specialist |
| **IHA089/drana-infinity-1.5b** | 1.0 GB | `ollama pull IHA089/drana-infinity-1.5b` | Ultra-light, quick recon queries, fully offline |
| **xploiter/pentester** | 1.6 GB | `ollama pull xploiter/pentester` | Pentest methodology, OWASP, tool guidance, report writing |

---

#### ⚖️ Balanced (4–8 GB RAM)

| Model | Size | Ollama Pull Command | What it's for |
|-------|------|--------------------|----|
| **IHA089/drana-infinity-7b** ⭐ | 4.7 GB | `ollama pull IHA089/drana-infinity-7b` | Elite cybersecurity research, exploit logic, 32K context |
| **ALIENTELLIGENCE/whiterabbitv2** | 4.7 GB | `ollama pull ALIENTELLIGENCE/whiterabbitv2` | AI hacking assistant (Llama 3.1 8B), 128K context, red/blue team |
| **loading_ctf/ctf-player_elona** | 4.4 GB | `ollama pull loading_ctf/ctf-player_elona` | CTF specialist — binary exploitation, network security, crypto |
| **luisppb16/gemma4-e4b-SecOps** | 5.3 GB | `ollama pull luisppb16/gemma4-e4b-SecOps` | Gemma 4 SecOps fine-tune, OWASP/NIST/CVSS, 128K context |

---

#### 💪 Capable (8–16 GB RAM)

| Model | Size | Ollama Pull Command | What it's for |
|-------|------|--------------------|----|
| **xploiter/the-xploiter** ⭐ | 9.2 GB | `ollama pull xploiter/the-xploiter` | Powerful offensive security — 13B, red team, bug bounty, AD attack paths, OWASP |
| **luisppb16/qwen3.5-9b-red-team** | 5.5 GB | `ollama pull luisppb16/qwen3.5-9b-red-team` | Qwen 3.5 red team fine-tune, adversary simulation, attack planning |
| **supergoatscriptguy/mythos-sec:8b** | 6.6 GB | `ollama pull supergoatscriptguy/mythos-sec:8b` | CTF, bug bounty, pentest — abliterated Gemma-4 base, 256K context, no disclaimers |
| **CyberCrew/notmythos-8b** | 6.0 GB | `ollama pull CyberCrew/notmythos-8b` | Defensive + offensive, tool-calling enabled, detection engineering |

---

#### 🚀 High-End (16+ GB RAM)

| Model | Size | Ollama Pull Command | What it's for |
|-------|------|--------------------|----|
| **supergoatscriptguy/mythos-sec:24b** ⭐ | 14 GB | `ollama pull supergoatscriptguy/mythos-sec` | Flagship: Liquid AI LFM2 MoE, 32K context, tool-calling, no disclaimers — `:latest` |
| **xploiter/the-xploiter** | 9.2 GB | `ollama pull xploiter/the-xploiter` | Most powerful offensive model — 13B ArchLlama, AD, cloud, OWASP exploitation |
| **luisppb16/qwen3.5-9b-red-team** | 5.5 GB | `ollama pull luisppb16/qwen3.5-9b-red-team` | Qwen 3.5 red team specialist, elite function calling, adversary simulation |
| **ALIENTELLIGENCE/whiterabbitv2** | 4.7 GB | `ollama pull ALIENTELLIGENCE/whiterabbitv2` | WhiteRabbitNeo hacking assistant, 128K context, red/blue team |

> ⭐ = Wizard default recommendation for this tier

---

## 📂 Your New Workspace Layout

Once the wizard finishes, it creates a neat, organized workspace in your home directory (`~/.siyarix/`). Here is a peek at what lives inside:

```text
~/.siyarix/
├── 🎭 personas/           # Core AI personality definitions
├── 🛠️ profiles/           # AI provider profiles
├── 🧠 memory/             # The Knowledge Graph (how Siyarix remembers past scans)
├── 📝 logs/sessions/      # Standard session logs
├── 🔒 logs/audit/         # Your tamper-evident audit trail
├── ⚡ cache/              # Cached tool outputs, DNS, and intel
├── 📊 templates/          # Customizable templates for reports and playbooks
├── 🛡️ playbooks/          # Your saved automated IR playbooks
├── 💾 sessions/           # Saved sessions you can resume later
└── ⚙️ settings.toml       # Your central configuration file
```

---

## 🤖 Unattended / CI Setup

Setting up Siyarix in a CI/CD pipeline or a headless server? You can bypass the interactive wizard entirely using environment variables and direct configuration commands:

```bash
# 1. Set the provider via environment variables
export MODEL_PROVIDER=openai
export OPENAI_API_KEY=sk-...

# 2. Tell Siyarix to use that provider
siyarix config set model_provider openai

# 3. Securely store the key
siyarix auth set-key openai
```

---

## ⏭️ Next Steps

Now that your wizard is complete, the fun begins!

- **[Your First Run](getting-started-first-run)** — Let's launch your very first automated scan.
- **[Setup & Configuration](getting-started-setup)** — Want to tweak the settings you just made? Read this guide.
