# SPDX-License-Identifier: AGPL-3.0-or-later

"""Templates and constants for the Siyarix onboarding wizard."""

SIYARIX_LOGO = r"""
   ███████   ███   ██   ██  █████  ██████    ███   ██   ██
   ██         █     ██ ██  ██   ██ ██  ██     █     ██ ██
   ███████    █      ███   ███████ █████      █      ███
        ██    █       █    ██   ██ ██ ██      █     ██ ██
   ███████   ███      █    ██   ██ ██  ██    ███   ██   ██

                       [bold white]SIYARIX[/bold white]
              [dim]CLI-Based AI Cybersecurity Orchestration Agent[/dim]
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
    ("openssl", "openssl", "TLS/SSL & cryptography"),
    ("dig", "dnsutils", "DNS resolution & enumeration"),
    ("whois", "whois", "WHOIS domain lookups"),
    ("python3", "python3", "Python scripting & automation"),
    ("jq", "jq", "JSON query & processing"),
    ("ping", "iputils-ping", "Network connectivity testing"),
    ("tcpdump", "tcpdump", "Packet capture & analysis"),
    ("tshark", "tshark", "CLI packet analyzer"),
]

PERSONA_TOOLS = {
    "appsec": [
        ("ffuf", "ffuf", "Web fuzzer"),
        ("nuclei", "nuclei", "Vulnerability scanner"),
        ("sqlmap", "sqlmap", "SQL injection automation"),
        ("gobuster", "gobuster", "Directory/file brute forcing"),
        ("nikto", "nikto", "Web server vulnerability scanner"),
        ("wpscan", "wpscan", "WordPress security scanner"),
        ("whatweb", "whatweb", "Web tech fingerprinting"),
    ],
    "network security": [
        ("masscan", "masscan", "High-speed TCP port scanner"),
        ("bettercap", "bettercap", "Network MITM framework"),
        ("responder", "responder", "LLMNR/NBT-NS poisoning"),
    ],
    "red team": [
        ("john", "john", "Password cracking"),
        ("hydra", "hydra", "Online password attacks"),
        ("hashcat", "hashcat", "GPU-accelerated hash cracking"),
        ("metasploit", "metasploit", "Exploitation framework"),
        ("mimikatz", "mimikatz", "Windows credential extraction"),
        ("impacket", "impacket", "Windows protocol toolkit"),
        ("crackmapexec", "crackmapexec", "AD post-exploitation"),
    ],
    "blue team": [
        ("yara", "yara", "Pattern matching for malware"),
        ("suricata", "suricata", "Network IDS/IPS engine"),
        ("snort", "snort", "Network intrusion detection"),
        ("ossec", "ossec", "Host-based intrusion detection"),
        ("wireshark", "wireshark", "Network protocol analyzer"),
    ],
    "dfir": [
        ("yara", "yara", "Pattern matching for malware"),
        ("volatility", "volatility", "Memory forensics framework"),
        ("sleuthkit", "sleuthkit", "File system forensics"),
        ("exiftool", "exiftool", "Metadata extraction"),
        ("binwalk", "binwalk", "Firmware analysis"),
        ("hashdeep", "hashdeep", "File hashing & integrity"),
    ]
}

CYBER_TOOL_HOMEPAGES = {
    "nuclei": "https://github.com/projectdiscovery/nuclei",
    "sqlmap": "https://sqlmap.org",
    "john": "https://www.openwall.com/john/",
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
    "masscan": "https://github.com/robertdavidgraham/masscan",
    "hashcat": "https://hashcat.net/hashcat/",
    "metasploit": "https://www.metasploit.com/",
    "mimikatz": "https://github.com/gentilkiwi/mimikatz",
    "responder": "https://github.com/lgandx/Responder",
    "impacket": "https://github.com/fortra/impacket",
    "crackmapexec": "https://github.com/byt3bl33d3r/CrackMapExec",
    "volatility": "https://www.volatilityfoundation.org/",
    "sleuthkit": "https://www.sleuthkit.org/",
    "binwalk": "https://github.com/ReFirmLabs/binwalk",
    "suricata": "https://suricata.io/",
    "snort": "https://www.snort.org/",
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
    "command_review": False,
    "history_days": 90,
    "log_level": "warning",
    "auto_update": True,
}
