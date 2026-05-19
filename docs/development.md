# Local Development Guide

Want to hack on Phalanx locally? Awesome! We've tried to make the setup as painless as possible for contributors of all skill levels. 

Phalanx is built with Python, and we target Python 3.11+ to take advantage of modern features like robust `asyncio` and advanced type hinting.

---

## 🚀 Quick Setup

The easiest way to get started is by using standard Python tools. We use `hatchling` as our build backend under the hood, but standard `pip` works perfectly.

1. **Clone the repo and enter the folder**
   ```bash
   git clone https://github.com/CosmicSec-Lab/phalanx.git
   cd phalanx
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

Run `phalanx` in your terminal to open the interactive shell, and type:
```text
/key set gemini your-api-key
```
Phalanx will encrypt it in your local `~/.phalanx/` directory and also generate a `.env` file in the project root for local development convenience. **The `.env` file is in our `.gitignore`, so you are perfectly safe from accidentally leaking it!**

---

## 🏗️ Code Organization

If you're wondering where to look, here's a quick map of the codebase:
- `src/phalanx/main.py`: The Typer entry point for the CLI. Start here to see how commands are routed.
- `src/phalanx/chat.py`: Where the interactive UI and slash commands live.
- `src/phalanx/core/`: The "brains" of the operation. This holds the task planner (which talks to the LLMs) and the execution engine (which spawns subprocesses).
- `src/phalanx/parsers/`: Small scripts that take the raw stdout of tools like `nmap` and convert them into structured JSON.
- `tests/`: Where all our `pytest` unit tests live.

---

## 🧪 Running E2E and Live Tests

To guarantee that the Phalanx agent operates reliably across different environments and operating system backends, we have developed a high-fidelity **End-to-End (E2E) and Live Testing Suite** located at [test_e2e.py](file:///d:/Miraz_Work/CosmicSec-Lab/nexsec/tests/test_e2e.py). 

Unlike standard unit tests, these E2E tests execute entire orchestration flows, planning passes, and interpreter pipelines inside **secure, mock-sandboxed environments**. This design allows you to run all tests fully offline in secure environments without making active network requests, installing package dependencies, or making modifications to your host operating system.

### The 4 Core E2E Scenarios

Our testing suite validates the following critical agent behaviors:

1. **CLI Dry-Run Scans (`test_cli_scan_dry_run`)**:
   Validates direct CLI `scan` execution using the `--dry-run` and `--no-banner` flags. It exercises command routing (via Typer and Click's `CliRunner`), target validation, and initial plan assembly to ensure that plans are generated correctly without triggering actual tool execution.
   
2. **Conditional Natural Language Workflows (`test_cli_run_conditional_workflow`)**:
   Verifies the parsing, routing, and execution of conditional instructions (e.g., `"if port_80_open then scan 127.0.0.1 with nikto else scan 127.0.0.1 with nmap"`). This ensures the interpreter properly evaluates pre-conditions and routes the task branches dynamically.

3. **Interactive Auto-Installation Interceptors (`test_interactive_installation_confirm`)**:
   Simulates scenarios where required tools are missing. By patching system environment checks, it validates two distinct interaction paths:
   - **Confirmed Branch**: The user approves the interactive prompt, which triggers the automatic package-installer pipeline (simulating `winget` on Windows, or other system installers) and returns a successful installation signal.
   - **Declined Branch**: The user declines the prompt, and the agent gracefully aborts without making any system changes or installations.

4. **Live Tool Fallback and Self-Correction (`test_live_tool_fallback_recovery`)**:
   Validates how the plan mutator handles real-world failure states and zero-finding outcomes:
   - **Self-Correction**: If a tool (like `nmap`) fails due to a host ping block, the live planner adapts the plan on the fly and schedules a retry using ping bypass (`-Pn`).
   - **Fallback Routing**: If a fuzzer (like `gobuster`) yields zero discoveries, the engine automatically schedules a fallback scan using a web vulnerability scanner (like `nikto`) to guarantee complete coverage.

### How to Run the Tests

You can execute these tests using `pytest` from your terminal with your virtual environment active:

```bash
# Run only the E2E tests
pytest tests/test_e2e.py -v

# Run a specific E2E test scenario
pytest tests/test_e2e.py -k "test_live_tool_fallback_recovery" -v

# Run all test suites in the repository
pytest
```

### Writing New E2E Tests

If you are developing new security workflows, platform resolvers, or shell wrappers, we highly recommend adding a corresponding E2E test:
- **Prioritize Offline Safety**: Never let tests call actual network endpoints or run mutable system commands. Use standard library mocking tools (`unittest.mock.patch`) to mock files, installer availability (`shutil.which`), and process execution (`run_tool_complete`).
- **Focus on Adaptability**: Write tests that verify how the engine *adapts* to failed steps, exit codes, and output patterns, ensuring the agent stays smart and resilient.

---

## 🧹 Code Quality

We use [Ruff](https://docs.astral.sh/ruff/) to keep the code formatted and clean. Before opening a Pull Request, it's a good idea to check your code by running:

```bash
ruff check .
```

### Need Help?
If you ever get stuck, see weird test failures on your specific OS, or just want to bounce an architectural idea around, open an issue or a Draft PR! We are very happy to help you figure it out.

