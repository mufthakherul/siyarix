# SPDX-License-Identifier: AGPL-3.0-or-later

"""Templates and constants for the Siyarix onboarding wizard."""

SIYARIX_LOGO = """
[bold cyan]
   \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
   \u2551                                                  \u2551
   \u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552 \u2588\u2588\u2552\u2552\u2588\u2588\u2552\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2588\u2588\u2552\u2550\u2550\u2550\u2550\u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552 \u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552 \u2552\u2588\u2588\u2588\u2588\u2552 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2552\u2550\u2550\u2550\u2550\u2588\u2588\u2552\u2588\u2588\u2552  \u2552\u2588\u2588\u2552  \u2588\u2588\u2552\u2552\u2550\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552   \u2588\u2588\u2552   \u2588\u2588\u2552  \u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2552\u2550\u2550\u2550\u2550\u2550\u2550\u2552\u2552\u2550\u2552   \u2552\u2550\u2552   \u2552\u2550\u2552  \u2552\u2550\u2552\u2552\u2550\u2550\u2550\u2550\u2550\u2552\u2552\u2550\u2552\u2552\u2550\u2552  \u2551
   \u2551                                                  \u2551
   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
[/bold cyan]
"""

WELCOME_PANEL_TEXT = """[bold yellow]First-Time Setup Wizard[/bold yellow]

Welcome to [bold cyan]Siyarix[/bold cyan] — your open-source
cybersecurity command center.

This wizard will help you configure Siyarix for your
environment in just a few steps."""

ETHICS_PLEDGE_TEXT = """[bold red]Ethical Use Pledge[/bold red]

Siyarix is a [bold]cybersecurity tool[/bold] designed for:
  • Authorized penetration testing
  • Security research on systems you own or have
    explicit permission to test
  • Educational purposes

[italic]Unauthorized use of this tool against systems
without permission is illegal and unethical.[/italic]

By continuing, you agree to use Siyarix responsibly
and only on systems you have authorization to test."""

EXIT_GREETING_TEXT = """[yellow]Exiting setup.[/yellow]

You can run the setup again at any time with:
[bold]  siyarix init[/bold]

[italic]Stay curious. Stay ethical.[/italic]"""

ONLINE_PROVIDERS = [
    ("openai", "OpenAI", "GPT-5 series, o-series"),
    ("anthropic", "Anthropic", "Claude Opus/Sonnet/Haiku"),
    ("gemini", "Google Gemini", "Gemini 2.0/2.5/2.5-Lite/3.0/3.1/3.1-Lite/3.5 series"),
    ("groq", "Groq", "Llama, Mixtral — fast inference"),
    ("together", "Together AI", "Llama, DeepSeek, open models"),
    ("openrouter", "OpenRouter", "Unified API for 200+ models"),
    ("deepseek", "DeepSeek", "DeepSeek V4/V3 series"),
    ("xai", "xAI (Grok)", "Grok 4 series"),
    ("mistral", "Mistral AI", "Mistral Large/Pixal"),
    ("perplexity", "Perplexity", "Sonar models"),
    ("azure", "Azure OpenAI", "GPT via Azure"),
]

OFFLINE_PROVIDERS = [
    ("ollama", "Ollama", "Local LLM runner — recommended"),
    ("lmstudio", "LM Studio", "GUI-based local model runner"),
    ("llamacpp", "llama.cpp", "C++ LLM inference server"),
    ("vllm", "vLLM", "High-throughput LLM serving"),
    ("localai", "LocalAI", "OpenAI-compatible local API"),
]

REQUIRED_TOOLS = [
    ("curl", "curl", "HTTP requests & API communication"),
    ("git", "git", "Version control & tool downloads"),
]

MINIMAL_CYBER_TOOLS = [
    ("nmap", "nmap", "Network discovery & port scanning"),
    ("curl", "curl", "HTTP requests & API testing"),
    ("dig", "bind-tools/dnsutils", "DNS resolution & enumeration"),
    ("openssl", "openssl", "TLS/SSL & cryptography"),
    ("whois", "whois", "WHOIS domain lookups"),
    ("nuclei", "nuclei", "Vulnerability scanner"),
    ("sqlmap", "sqlmap", "SQL injection automation"),
    ("john", "john", "Password cracking"),
    ("hydra", "hydra", "Online password attacks"),
]

CYBER_TOOL_HOMEPAGES = {
    "nuclei": "https://github.com/projectdiscovery/nuclei",
    "sqlmap": "https://sqlmap.org",
    "john": "https://www.openwall.com/john/",
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
}

ARCH_MAP: dict[str, str] = {
    "AMD64": "x86_64 (64-bit)",
    "x86_64": "x86_64 (64-bit)",
    "x86": "x86 (32-bit)",
    "i386": "x86 (32-bit)",
    "i686": "x86 (32-bit)",
    "arm64": "ARM64 (AArch64)",
    "aarch64": "ARM64 (AArch64)",
    "armv7l": "ARM (32-bit)",
    "armv6l": "ARM (32-bit)",
    "ARM64": "ARM64 (AArch64)",
}

PM_CHECKS: list[tuple[str, str]] = [
    ("winget", "winget"),
    ("choco", "choco"),
    ("apt-get", "apt"),
    ("apt", "apt"),
    ("brew", "brew"),
    ("pkg", "pkg"),
    ("pacman", "pacman"),
    ("dnf", "dnf"),
    ("yum", "yum"),
    ("apk", "apk"),
    ("port", "macports"),
    ("nix-env", "nix"),
    ("scoop", "scoop"),
]

DEFAULT_PREFERENCES = {
    "theme": "default",
    "output_format": "table",
    "notifications": True,
    "stealth_mode": False,
    "command_review": True,
    "history_days": 90,
    "log_level": "warning",
    "auto_update": True,
}
