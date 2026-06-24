# 🧠 Responsible AI Usage Policy

Siyarix experiments with Artificial Intelligence to plan tasks and assist operators. Because AI is unpredictable, this policy outlines how I try to handle AI responsibly within the platform.

## 🏗️ How We Use AI

1. **Task Planning:** Trying to convert natural language goals into execution plans.
2. **Interactive Chat:** Providing an assistant interface.

## 👁️ Human Oversight is Mandatory

AI is an assistant, not an autopilot. 
- **The Permission Gate:** Every command is checked before execution.
- **User Confirmation:** If the AI suggests a dangerous command, execution halts, and you must explicitly approve it.

> [!CAUTION]
> **You are legally responsible for the commands you authorize.** Never blindly approve a command you do not fully understand.

## ⚠️ Known Limitations of AI

Current AI models can be flawed. Be aware that the AI may:
- Generate incorrect execution plans.
- Suggest tools that aren't installed.
- Misinterpret your intent.
- **Hallucinate** fake flags or IP addresses.

## 🛡️ Data Protection & Privacy

When you use cloud-based AI providers (like OpenAI or Gemini), data leaves your machine. 
- Siyarix uses a lightweight DLP engine to try to mask basic credentials before they hit the internet.
- For maximum privacy, Siyarix supports local, offline models (via Ollama or LM Studio) so your data never leaves your laptop.

## 🚩 Reporting AI Misbehavior

If the AI suggests something harmful or hallucinates dangerously:
- Please open an issue on the [GitHub Repository](https://github.com/mufthakherul/siyarix/issues).
- **Do not include actual credentials in your bug report!**

## ⚖️ Your Ethical Obligations

By using Siyarix's AI features, you agree to:
- **Never** use the AI to generate targeted phishing campaigns.
- **Never** prompt the AI to write destructive malware.
- **Never** attack systems outside your authorized scope.
