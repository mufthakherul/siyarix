# Architecture & Internals

Phalanx is designed to be modular and transparent. We wanted to build a system that bridges the gap between natural language processing and actual command-line execution, without making the codebase overly complex or difficult for a student to understand.

Here is a comprehensive breakdown of how Phalanx works under the hood.

---

## 🧩 Architectural Layers

Phalanx is broken down into several distinct layers, each handling a specific part of the user journey.

### 1. The CLI & Presentation Layer
- **Typer Framework**: We use [Typer](https://typer.tiangolo.com/) to build the command-line interface. It's clean, relies on standard Python type hints, and is easy to maintain.
- **Rich Integration**: For all the beautiful terminal output, syntax-highlighted JSON, colors, and interactive components, we rely heavily on the [Rich](https://rich.readthedocs.io/) library. This ensures the output is always readable and visually appealing.

### 2. The Interactive Chat Experience (REPL)
When you run `phalanx` without any arguments, you drop into an interactive REPL (Read-Eval-Print Loop).
- **Session Management**: This layer acts as a friendly AI assistant that keeps track of your session history. It remembers previous commands and contextual data so you can have an ongoing conversation.
- **Slash Commands**: To make configuration fast, we built a slash-command router (e.g., `/help`, `/theme mode dark`, `/key set`). These bypass the AI planner and execute Python functions directly for immediate feedback.

### 3. Orchestration & Planning (The "Brain")
This is where the magic happens when you ask Phalanx to perform a security task.
- **Task Planner**: This module takes your plain-English instructions and passes them to a Large Language Model (LLM). It instructs the model to break down your request into a logical, structured sequence of execution steps (JSON). 
- **Execution Engine**: This component takes the structured steps from the Task Planner and executes them. It handles the heavy lifting: spawning subprocesses, catching `stdout`/`stderr`, managing retries if a command fails, and ensuring that step dependencies are respected (e.g., waiting for a port scan to finish before launching a web fuzzer).
  - **Auto-Installation**: When a required tool is missing but a system installer (such as `winget` on Windows, or other native platform managers) is available on the `PATH`, the engine prompts the user for permission. If approved, it automatically installs the missing tool and resumes execution.
  - **Plan Mutation & Self-Correction**: If a step fails (e.g., a target host blocks default ping probes) or yields zero findings, the engine's internal mutator automatically adapts the plan on the fly (e.g., retrying with `-Pn` or scheduling fallback scanners like `nikto`).

### 4. Security & Knowledge Base
To make the AI useful, we have to provide it with real-world constraints.
- **Shell Knowledge Library**: A heuristic engine that detects your operating system and terminal type. It translates general security "intents" into native commands for Bash, PowerShell, Zsh, or CMD. This ensures that Phalanx works natively on Windows just as well as it does on Kali Linux.
- **Tool Registry**: Upon startup, this component scans your system's `PATH` to discover which security tools (like `nmap`, `nuclei`, or `ffuf`) you already have installed. It feeds this list to the Task Planner, ensuring the AI only recommends tools you can actually run.
- **Enterprise Credential Vault**: A secure local storage system (`~/.phalanx/`) that uses symmetric encryption (Fernet) to protect your API keys. We explicitly designed this to keep your keys out of your shell history and out of public dotfiles.

---

## 🔄 The Execution Workflow

If you type `phalanx run "find open ports on example.com"`, here is the exact lifecycle of that command:

1. **Intent Parsing**: The CLI captures your string and sends it to the Task Planner.
2. **Context Gathering**: The Tool Registry reports that `nmap` is installed. The Shell Knowledge Library reports that you are running `zsh` on macOS.
3. **Model Generation**: The Task Planner sends a prompt to the LLM (e.g., Gemini or OpenAI) containing your request and the context.
4. **Plan Creation**: The LLM returns a structured JSON payload defining a step to run `nmap -p- example.com`.
5. **Safety Verification**: The Execution Engine intercepts the planned step and checks it against a list of dangerous patterns (e.g., blocking `rm -rf`).
6. **Execution**: The Execution Engine spawns a subprocess, runs `nmap`, captures the output, and prints the formatted results to your terminal using Rich.

---

## 🧪 High-Fidelity E2E Validation Pipeline

To ensure the architectural integrity of our planning and execution engines under real-world scenarios, we maintain a comprehensive **End-to-End (E2E) and Live testing pipeline**. 

This validation suite runs in a **mock-sandboxed environment**, allowing us to simulate external system states, CLI entry points, process executions, and user interactions:
- **CLI dry-run validation**: Verifies Typer/Click command routing and input parsing using Click's `CliRunner`.
- **Dynamic Branching**: Asserts that the rules interpreter correctly evaluates pre-conditions and routes complex natural language conditionals correctly.
- **Auto-Installation Flow**: Simulates system installer detection (like `winget` on Windows) and verifies prompt confirmation intercepts (confirmed vs declined branches).
- **Execution Self-Correction**: Simulates step failures and empty results to verify that plan mutators automatically adapt the running plan on the fly.

This offline-safe, non-destructive test suite allows developers to iterate safely, knowing that the engine will behave consistently across both Windows and Unix environments.

---

## 🧠 Core Design Principles

When we started this project, we wanted to stick to a few core ideas that foster learning and safety:

- **Safety Over Magic**: We want the AI to suggest and execute *verified* tool invocations rather than just hallucinating random shell commands. Phalanx will always verify a tool exists and passes safety checks before pulling the trigger.
- **Platform Friendly**: Whether you're a student running Windows or a researcher on a Linux VM, the core commands should work consistently.
- **Learn by Doing**: The architecture is designed to be transparent. By setting `PHALANX_LOG_LEVEL=DEBUG`, you can watch exactly how Phalanx builds its plans and learn how different security tools chain together in the real world.
- **Welcoming UX**: We believe security tools don't have to look intimidating. A polished, friendly interface lowers the barrier to entry for beginners and makes the terminal a more pleasant place to be.
