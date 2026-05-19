# Getting Started with Phalanx

Hey there! Setting up Phalanx is designed to be straightforward. Because the core engine is built in Python, you can run it natively on almost any operating system (Linux, macOS, or Windows). 

Below are the detailed instructions for getting your environment set up perfectly.

---

## 🛠️ Prerequisites

Before you begin, ensure you have the following installed on your machine:
- **Python 3.11 or higher**: Phalanx relies on modern Python features (like `asyncio` and advanced type hinting).
- **A Package Manager**: Standard `pip` works great, but we highly recommend [uv](https://github.com/astral-sh/uv) if you want blazing-fast installations.

*(Optional but Recommended)*: 
- Have a few security tools installed on your `PATH` (e.g., `nmap`, `nuclei`, `ffuf`). Phalanx acts as a brain that orchestrates these tools, so the more tools you have installed natively, the more powerful Phalanx becomes!

---

## 📦 Installation Guide

We strongly recommend installing Phalanx inside an isolated virtual environment so it doesn't conflict with your system Python packages.

### Method 1: Standard Installation (via pip)

```bash
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate the virtual environment
source .venv/bin/activate        # Linux/macOS
.\.venv\Scripts\activate.ps1      # Windows (PowerShell)

# 3. Install Phalanx
pip install phalanx
```

### Method 2: Installing the "All-Batteries-Included" Version

If you want the absolute best experience (including the autonomous AI planner, rich interactive command palettes, and cross-platform terminal optimizations), you should install the optional extras:

```bash
pip install "phalanx[autonomous,cli]"
```

### Method 3: Installing from Source (For Developers & Contributors)

If you want to poke around the code, run the bleeding-edge development version, or contribute a bug fix:

```bash
git clone https://github.com/CosmicSec-Lab/phalanx.git
cd phalanx
python -m venv .venv
source .venv/bin/activate
pip install -e '.[all]'
```
*(The `-e` flag means "editable", so any changes you make to the code will immediately apply without needing to reinstall).*

---

## 🔑 Setting Up Your API Keys

Because Phalanx uses AI models to help plan your tasks, you'll need an API key for your preferred LLM provider (like Google Gemini, OpenAI, or Anthropic). You can also use Ollama for local, offline models!

Don't worry, your keys are stored securely in a local encrypted vault (`~/.phalanx/`). They are never sent anywhere without your permission.

**The Easiest Way to Configure Keys:**
1. Launch the interactive shell by typing:
   ```bash
   phalanx
   ```
2. Once the chat interface opens, use the slash command to securely save your key:
   ```text
   /key set gemini your-api-key-here
   ```
   *(You can replace `gemini` with `openai` or `anthropic` depending on your provider).*

3. Verify your configuration:
   ```text
   /key list
   ```

---

## 🎉 You're Ready!

That's it! You're ready to start exploring. We recommend checking out [usage.md](usage.md) next for some fun examples of what you can do with your newly configured agent.
