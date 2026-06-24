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
If you prefer raw power and speed, you can connect Siyarix to commercial APIs. 
*Supported:* OpenAI, Anthropic (Claude), Google Gemini, Groq, Together AI, DeepSeek, xAI (Grok), Mistral, and many more. 
*(Note: These require you to paste in your API key during setup).*

### 🏠 Local Offline Engines
Working in a sensitive environment? You can run Siyarix **100% offline** with zero data leaving your machine!
*Supported:* Ollama, LM Studio, llama.cpp, vLLM. 

**Hardware-Based Recommendations:**
If you choose to run local models, the wizard analyzes your available RAM and GPU to suggest the absolute best cybersecurity-tuned model for your machine:
- **≤ 4 GB RAM:** Lightweight models (e.g., `IHA089/drana-infinity-3b`)
- **4-8 GB RAM:** Balanced models (e.g., `IHA089/drana-infinity-7b`)
- **8-16 GB RAM:** Highly capable models (e.g., `supergoatscriptguy/mythos-sec:8b`)
- **16+ GB RAM:** High-end models (e.g., `supergoatscriptguy/mythos-sec:24b`)

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
