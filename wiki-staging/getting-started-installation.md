# 📦 Installation Guide

Welcome! We are thrilled you're ready to install Siyarix.

We have designed Siyarix to be as lightweight and universally compatible as possible. Whether you are running a high-powered security workstation, a cloud instance, or even a mobile device, we have got you covered.

---

## 🛠️ System Requirements

Before we begin, let's make sure your system is ready:
- **Python:** Version **3.11 or later** is required.
- **Memory (RAM):** Minimum 512 MB, but we **strongly recommend 4 GB+** if you plan on running intensive, multi-wave AI autonomous operations.
- **Storage:** ~500 MB of free disk space is recommended to comfortably house the security tool dependencies Siyarix might download.
- **Operating Systems Supported:**
  - Linux (Debian, Ubuntu, Kali, Arch, etc.)
  - macOS
  - Windows (PowerShell 5.1+)
  - Mobile: Android (via Termux), iOS (via iSH), and HarmonyOS.

---

## 🚀 The Fastest Way: PyPI (Recommended)

The easiest and most common way to install Siyarix is directly through Python's package manager, `pip`.

Open your terminal and run:

```bash
pip install siyarix
```

### ✨ Optional "Extras" Packages

By default, the command above installs the core engine. However, Siyarix is highly modular! You can install specific "extras" to pull in SDKs for your favorite AI providers or extra UI components.

*Just append the extra in brackets like this: `pip install "siyarix[extra_name]"`*

| Extra Name | What it installs for you |
|-------|----------|
| `autonomous` | **(Highly Recommended)** Installs the official SDKs for OpenAI, Anthropic, and Google Gemini all at once for peak autonomous performance. |
| `openai` | Just the OpenAI SDK. |
| `anthropic` | Just the Anthropic (Claude) SDK. |
| `gemini` | Just the Google Generative AI SDK. |
| `cli` / `terminal`| Pulls in `Typer`, `Rich`, `prompt_toolkit`, and `Textual` for the ultimate terminal experience. |
| `security` | Installs `Bandit`, `Safety`, and `pip-audit` for internal security checks. |
| `windows` | Adds necessary Windows-specific dependencies like `colorama` and `pywin32`. |
| `all` | **(The Kitchen Sink)** Installs absolutely every optional dependency available. |
| `dev` | Installs everything you need to contribute code (`pytest`, `ruff`, `mypy`, `pre-commit`). |

**Example Installations:**
```bash
# I want to use OpenAI, Gemini, and Claude seamlessly:
pip install "siyarix[openai,gemini,anthropic]"

# Give me everything you've got!
pip install "siyarix[all]"
```

---

## 📦 Package Managers

If you prefer using your operating system's native package manager, we support those too!

> [!NOTE]
> *Note for new GitHub Organization: Remember to use the updated `siyarix/siyarix` repository URLs if you are pulling directly from source!*

### macOS (Homebrew)
```bash
brew install --build-from-source packages/homebrew/siyarix.rb
```

### Windows (Winget)
```bash
winget install Mufthakherul.Siyarix
```

### Windows (Chocolatey)
```bash
choco install siyarix
```

### Debian / Ubuntu / Kali Linux
```bash
sudo dpkg -i packages/deb/siyarix_1.0.1-1_all.deb
```

### Docker
Perfect for ephemeral, isolated security environments.
```bash
docker pull siyarix:latest

# Run Siyarix directly through the container:
docker run -it siyarix:latest --help
```

---

## 💻 Building Directly From Source

Are you a developer or just prefer living on the bleeding edge? You can build Siyarix directly from our GitHub repository.

```bash
# 1. Clone the repository
git clone https://github.com/siyarix/siyarix.git

# 2. Enter the directory
cd siyarix

# 3. Create a fresh virtual environment
python -m venv .venv

# 4. Activate the virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.\.venv\Scripts\Activate.ps1

# 5. Install in editable mode with all features
pip install -e ".[all,cli,siem]"
```

---

## ⚡ Automated Platform Install Scripts

If you want an absolutely hands-off setup, we provide one-liner install scripts that automatically detect your OS, set up a virtual environment, and install Siyarix for you.

```bash
# 🐧 Linux, 🍏 macOS, 🌐 ChromeOS, 🍎 iOS/iSH, 🌐 HarmonyOS, BSD
curl -fsSL https://siyarix.github.io/installer/install.sh | bash

# 🪟 Windows (Run this in PowerShell)
irm https://siyarix.github.io/installer/install.ps1 | iex

# 📱 Android (Run inside the Termux app)
curl -fsSL https://siyarix.github.io/installer/install-termux.sh | bash
```

---

## ✅ Verifying Your Installation

Once the installation finishes, let's make sure everything is working perfectly. Run the following commands in your terminal:

```bash
# Check the installed version
siyarix --version

# View the comprehensive help menu
siyarix --help
```

If you see the help menu, **congratulations! 🎉** Siyarix is successfully installed on your machine.

---

## ⏭️ Next Steps

Now that you have the platform installed, it's time to wire up its brain!

Head over to the **[Onboarding Wizard](getting-started-onboarding)** guide. Siyarix features an incredible 11-step interactive wizard that will guide you through setting up your AI provider API keys and checking your local security tools.
