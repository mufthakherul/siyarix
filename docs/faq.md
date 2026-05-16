# FAQ

Q: What is NexSec?
A: NexSec is a lightweight AI-powered security agent by CosmicSec-Lab that helps automate scanning, hunting, and incident workflows.

Q: Is NexSec safe to run in production?
A: Use appropriate credentials and sandboxing. Some scanning tools may produce noisy traffic; obtain permission before scanning external networks.

Q: How do I add new tools?
A: Implement a parser adapter under `src/nexsec/parsers` and register it in `tool_registry.py`.
