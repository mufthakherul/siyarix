# FAQ

**Q: What is NexSec?**
A: NexSec is a lightweight, autonomous security agent developed by CosmicSec-Lab. It automates security scanning, threat hunting, and incident workflows through intelligent task orchestration. Running `nexsec` by itself opens an assistant-style command center for interactive use.

**Q: Is NexSec safe to run in production environments?**
A: Yes, provided you use appropriate credentials and sandboxing. The execution engine includes a safety resolver to block dangerous commands, but operators should always obtain proper authorization before scanning production networks.

**Q: How do I add support for new security tools?**
A: You can add new tools by implementing a parser adapter in the `parsers` directory and registering the tool in the `tool_registry`. Autonomous discovery can also pick up tools added to your system PATH.

**Q: Which model providers are supported for autonomous planning?**
A: NexSec currently supports OpenAI, Google Gemini, Anthropic, Ollama (local), and NexSec Cloud providers.

**Q: How do I change the theme or preview the UI?**
A: Use `/theme mode <system|dark|light|minimal|neon>` inside chat, or `nexsec theme preview` from the CLI.

**Q: How do I store API keys without editing env files manually?**
A: Use `nexsec auth set-key <provider> --key <value>` or the chat `/key set <provider> <api_key>` command. NexSec stores the key in the encrypted credential vault and syncs the matching variable into `.env`.
