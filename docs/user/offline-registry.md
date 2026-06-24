# 📴 Offline / Registry Mode

Operating in an air-gapped environment? API keys expired? Don't worry! Siyarix is built to function beautifully even when completely disconnected from AI providers.

When no AI provider is connected, or when you explicitly use `--mode offline` or `--mode registry`, Siyarix seamlessly switches to its deterministic **Registry Mode**. No LLM required!

---

## ⚙️ How It Works

Without an AI to interpret intent, Siyarix falls back on intelligent heuristics and pre-defined workflows:

1. **Intent Parsing**: The `RegistryPlanner` analyzes your instruction against a massive library of approximately 450 keyword patterns and 15 workflow templates.
2. **Safe Execution**: The `RegistryExecutor` runs each step through the `ToolRegistry`, ensuring full compliance with safety guardrails and Data Loss Prevention (DLP) rules. It even handles automatic alternative tool fallback if your primary tool is missing!
3. **Local Storage**: All results are saved directly to the `OfflineStore` (a local SQLite database), allowing you to review findings and diff results across multiple scans later.

---

## 🕵️ The Deep Scan

One of the most powerful offline features is the `scan-deep` command. It runs a progressive, 4-pass security assessment:

1. **Discovery**: Identifies live hosts and performs a full port sweep.
2. **Fingerprint**: Detects operating systems, determines service versions, and runs default scripts.
3. **Vulnerability**: Runs template-based vulnerability scanners (like Nuclei or Nikto).
4. **Enumeration**: Performs deep directory, subdomain, and DNS enumeration.

> [!TIP]
> Siyarix runs these tools in parallel and will automatically swap to alternative tools if your preferred scanner isn't installed!

---

## 💻 Programmatic Usage

Building your own scripts? You can access the offline hints and messages directly:

```python
from siyarix.offline_registry import offline_instruction_hint, no_provider_message

# Get a heuristic hint for a command
hint = offline_instruction_hint("scan example.com")

# Get the standard "No AI Provider" warning message
msg = no_provider_message()
```

---

## 🛠️ Related Commands

Try out these commands to see the offline engine in action:

- **Run a scan offline**: `siyarix scan <target> --mode offline`
- **Run a full deep scan**: `siyarix scan-deep <target>`
- **Run deep discovery**: `siyarix discover <target> --deep`
- **Force registry execution**: `siyarix run "<instruction>" --mode registry`
