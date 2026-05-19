# Local Development Guide

Want to hack on Siyarix locally? Awesome! We've tried to make the setup as painless as possible for contributors of all skill levels. 

Siyarix is built with Python, and we target Python 3.11+ to take advantage of modern features like robust `asyncio` and advanced type hinting.

---

## 🚀 Quick Setup

The easiest way to get started is by using standard Python tools. We use `hatchling` as our build backend under the hood, but standard `pip` works perfectly.

1. **Clone the repo and enter the folder**
   ```bash
   git clone https://github.com/CosmicSec-Lab/siyarix.git
   cd siyarix
   ```

2. **Create a virtual environment**
   This ensures you don't mess up your system Python installation.
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate.ps1
   ```

3. **Install the project and development dependencies**
   We install using the `[all]` tag to get the optional features (like AI planners), and we install `pytest` and `ruff` for testing and linting.
   ```bash
   pip install -e '.[all]' pytest ruff
   ```
   *(The `-e` flag stands for editable, meaning changes you make to the Python files will take effect immediately without needing to reinstall).*

4. **Run the tests**
   Just to make sure everything works properly on your machine:
   ```bash
   pytest -q
   ```
   If all tests pass, you're good to go!

---

## 🔑 Managing API Keys Locally

To test the AI task planner, you'll need a valid API key (e.g., Gemini, OpenAI). We made a safe way to handle this so you don't accidentally commit your keys to GitHub:

Run `siyarix` in your terminal to open the interactive shell, and type:
```text
/key set gemini your-api-key
```
Siyarix will encrypt it in your local `~/.siyarix/` directory and also generate a `.env` file in the project root for local development convenience. **The `.env` file is in our `.gitignore`, so you are perfectly safe from accidentally leaking it!**

---

## 🏗️ Code Organization

If you're wondering where to look, here's a quick map of the codebase:
- `src/siyarix/main.py`: The Typer entry point for the CLI. Start here to see how commands are routed.
- `src/siyarix/chat.py`: Where the interactive UI and slash commands live.
- `src/siyarix/core/`: The "brains" of the operation. This holds the task planner (which talks to the LLMs) and the execution engine (which spawns subprocesses).
- `src/siyarix/parsers/`: Small scripts that take the raw stdout of tools like `nmap` and convert them into structured JSON.
- `tests/`: Where all our `pytest` unit tests live.

---

## 🧹 Code Quality

We use [Ruff](https://docs.astral.sh/ruff/) to keep the code formatted and clean. Before opening a Pull Request, it's a good idea to check your code by running:

```bash
ruff check .
```

### Need Help?
If you ever get stuck, see weird test failures on your specific OS, or just want to bounce an architectural idea around, open an issue or a Draft PR! We are very happy to help you figure it out.
