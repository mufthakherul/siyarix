# Troubleshooting

Things don't always work perfectly, especially when trying to orchestrate multiple external security tools across different operating systems. Here are some common issues and how to fix them!

---

## 🔍 Built-in Diagnostics

Before digging through dense log files, Siyarix has some built-in commands designed specifically to help you figure out what's wrong:

- **`siyarix health`**: This runs a full diagnostic sweep. It checks if your local SQLite databases are writable, if your encrypted vault is accessible, and if your configured AI endpoints are responding.
- **`siyarix shell doctor`**: This tells you exactly which external security tools (like `nmap`, `nuclei`, `ffuf`) Siyarix can actually see on your system `PATH`.

---

## 🔧 Common Issues

### "Tool not found" errors
If Siyarix tries to run a tool but fails, it almost certainly means the tool isn't in your system's environment `PATH`.
- **The Fix**: Try running the tool manually in your terminal (e.g., type `nmap`). If your terminal says "command not found", Siyarix can't use it either. Install the tool via your package manager (e.g., `apt`, `brew`, `winget`) and ensure it's on your `PATH`.

### API Key Failures or "Provider Error"
If the AI is failing to respond or throwing authentication errors:
- **Check your keys**: Type `/key list` inside the interactive chat to see what Siyarix is trying to use.
- **Check your billing**: Make sure you actually have credits or a valid billing method set up with your AI provider!
- **Re-set the key**: Try re-setting the key securely using `/key set gemini <your-key>` in the chat.
- **Network Issues**: Ensure you aren't behind a corporate proxy blocking outbound API calls to OpenAI/Google.

### The AI is doing weird things or failing to plan
Sometimes AI models get confused or hallucinate bad plans.
- **View the Logs**: You can turn on debug logging to see exactly what the AI is thinking and the raw JSON it is trying to return:
  ```bash
  export SIYARIX_LOG_LEVEL=DEBUG
  siyarix
  ```
- **Switch Models**: Smaller or older models struggle with complex JSON generation. If the AI is consistently failing, try switching to a larger model like GPT-4o or Gemini 1.5 Pro using `/model <name>`.

### The UI Looks Messed Up
If the colors look wrong or the tables are rendering strangely:
- **Terminal Support**: Ensure your terminal emulator supports 256 colors or TrueColor.
- **Change the Theme**: Try switching to a simpler interface with `siyarix theme set minimal` or `/theme mode minimal`. You can preview themes using `siyarix theme preview`.

---

## 🙋 Getting More Help

If you've tried the steps above and you're still stuck, don't worry!
- Run `siyarix --help` to see all available commands.
- Open an issue on our GitHub repository. The Mufthakherul community is very friendly and we're always happy to help you debug!
