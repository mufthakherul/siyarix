# 🏃‍♂️ Your First Run

You have installed Siyarix, and you are ready to take it for a spin. Awesome! 

This guide will walk you through your very first session, from verifying the system health to executing a live command.

---

## 1️⃣ Launch and Onboard

To get started, simply type the following into your terminal:

```bash
siyarix
```

If this is your very first time running the program, the **Onboarding Wizard** will automatically launch. It will warmly guide you through setting up your AI provider and configuring your initial preferences. 

*(If you want to read more about what happens during this step, check out our [Onboarding Wizard](getting-started-onboarding) guide.)*

---

## 2️⃣ Verify System Health

Before we start scanning networks, let's make sure everything is plugged in correctly. Siyarix has a built-in health checker that acts like a pre-flight checklist.

```bash
siyarix health
```

This command runs a comprehensive diagnostic sweep, checking:
- **System Requirements:** Ensuring your Python version and OS are compatible.
- **Installed Tools:** Scanning your `PATH` to make sure you have the necessary security binaries installed.
- **Credential Store:** Verifying that your encrypted vault is unlocked and ready.
- **Provider Connectivity:** Reaching out to your configured AI providers (like OpenAI or Ollama) to ensure their APIs are responding.
- **System Resources:** Checking your memory and CPU to warn you if you might run out of RAM during heavy autonomous operations.

If it says you are healthy, you are cleared for takeoff! 🛫

---

## 3️⃣ Run a Pre-Configured Scan

Let's start with something simple. Siyarix comes with a few pre-configured workflows. Let's run a quick port scan against a domain.

```bash
siyarix scan quick example.com
```

**What happens behind the scenes?**
1. Siyarix plans the operation.
2. It routes the plan through the **Permission Gate** (so you can see exactly what it is about to do).
3. It executes the tools in the background.
4. It parses the messy terminal output into a clean, structured table.

### Want to dig deeper?
If you want comprehensive reconnaissance (OS fingerprinting, vulnerability detection, etc.), try the deep scan:
```bash
siyarix scan deep example.com
```

---

## 4️⃣ Command with Natural Language

This is where the magic happens. Instead of typing out complex `nmap` flags, you can just tell Siyarix what you want to achieve in plain English.

```bash
siyarix run "enumerate services on 10.0.0.1 and find vulnerable versions"
```

The AI engine will interpret your request, select the best tools for the job, build an execution plan, and present you with the results.

### 🚫 Running Offline?
If you are in an air-gapped environment or don't want to use an AI provider, Siyarix has you covered. Just add the `--mode offline` flag:

```bash
siyarix --mode offline run "scan example.com"
```

In offline mode, Siyarix relies on a hardcoded heuristics registry to plan tasks—no AI dependency, and no API keys required!

---

## 5️⃣ Enter the Interactive REPL

Running single commands from the terminal is great, but Siyarix truly shines when you enter its interactive chat mode (the REPL). 

```bash
siyarix
```

Once inside, you are in a multi-turn conversation with your AI security co-pilot. You can:
- Type `/run [prompt]` to execute commands.
- Type `/persona` to change the AI's mindset on the fly.
- Enjoy context-aware tab completion for file paths, tools, and models!

---

## 🙋 Getting Help

If you ever get stuck, help is just a command away:

```bash
siyarix --help              # Top-level help menu
siyarix scan --help         # Help for a specific command
```

If you are inside the REPL, simply type `/help` to see a list of all available slash commands.

---

## ⏭️ What's Next?

You have successfully run your first scan! Here is where you can go from here:

- **[Interactive Chat (REPL)](../user/interactive-chat.md)** — Master the interactive terminal.
- **[Security Workflows](../user/security-workflows.md)** — Learn how to handle real-world scenarios.
- **[CLI Commands](../user/cli-commands.md)** — Browse the full command reference.
