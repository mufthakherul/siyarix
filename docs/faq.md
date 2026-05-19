# FAQ

**Q: What is NexSec?**
A: NexSec is a lightweight, autonomous security agent developed by CosmicSec-Lab. It automates security scanning, threat hunting, and incident workflows through intelligent task orchestration.

**Q: Is NexSec safe to run in production environments?**
A: Yes, provided you use appropriate credentials and sandboxing. The execution engine includes a safety resolver to block dangerous commands, but operators should always obtain proper authorization before scanning production networks.

**Q: How do I add support for new security tools?**
A: You can add new tools by implementing a parser adapter in the `parsers` directory and registering the tool in the `tool_registry`. Autonomous discovery can also pick up tools added to your system PATH.

**Q: Which model providers are supported for autonomous planning?**
A: NexSec currently supports OpenAI, Google Gemini, Anthropic, Ollama (local), and NexSec Cloud providers.
