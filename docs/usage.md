# How to Use Phalanx

Phalanx is designed to be a helpful companion in your terminal. You can use it as a traditional command-line tool, or you can drop into the interactive chat mode and converse with the AI natively. This document covers the most common workflows, from beginner explorations to advanced automation.

---

## 💬 The Interactive Chat (Recommended)

If you're new to Phalanx, or if you're trying to learn how a new security tool works, the absolute best way to use it is through the interactive chat. 

To start, simply type:

```bash
phalanx
```

This will launch a beautiful, clear landing screen and drop you into a conversational REPL (Read-Eval-Print Loop). From here, you can use natural language.

### Example Conversations
- *"Can you scan 192.168.1.1 for open ports? Explain what the ports do."*
- *"I'm looking for web vulnerabilities on example.com, what tools should we use?"*
- *"Help me understand what a CSRF attack is, and write me a small proof of concept script."*
- *"What security tools are currently installed on my system?"*

### Handy Slash Commands
While in the chat, you can use shortcuts (slash commands) to configure your environment quickly without leaving the session:
- `/help`: See all available commands.
- `/tools`: See which security tools (like Nmap, Nuclei, or Ffuf) Phalanx has discovered on your local `PATH`.
- `/key set gemini <your-key>`: Securely add your API key to the local encrypted vault.
- `/theme mode dark` (or `neon`, `minimal`): Customize the interface to match your terminal aesthetic.
- `/model gemini`: Switch the AI brain to use Gemini (or OpenAI, Ollama, etc.).
- `/target <ip_or_domain>`: Set a persistent target for the session so you don't have to keep typing it.

---

## ⚡ Direct Command Line Usage

If you just want to get things done quickly without opening the chat, you can pass natural language instructions directly to the `run` command. Phalanx will think for a moment, create a plan, run the necessary background tools, and output the result.

```bash
# Ask Phalanx to figure out the right tool to use
phalanx run "scan scanme.nmap.org and show me the open ports"

# Ask Phalanx to combine multiple tools
phalanx run "find subdomains for example.com and then check them for open ports"
```

---

## 🔍 Specific Security Scans

If you know exactly what you want to do and don't need the AI to plan it for you, you can invoke the execution engine directly. This is extremely useful for scripting!

```bash
# Run a specific tool against a single target
phalanx scan 10.0.0.1 --tool nmap

# Scan multiple targets from a text file
phalanx bulk scan targets.txt --tool nuclei

# Save the scan results into the local SQLite database for later review
phalanx scan example.com --tool ffuf --save
```

---

## 🛡️ Security Operations & Threat Hunting

Phalanx includes a suite of commands designed to help you manage security data locally.

```bash
# List open incidents you've recorded
phalanx security incidents --status open

# Manually report a new incident
phalanx security incident-create --title "Suspicious activity" --category intrusion --severity critical

# Run a MITRE-mapped threat hunt query against local logs
phalanx security hunt q_ps_exec --target win-srv-01
```

---

## 🖥️ Shell Translation Helper

One of the coolest educational features of Phalanx is that it understands the differences between Windows, Mac, and Linux terminals. If you ever forget how to do something in your current shell, you can ask Phalanx to translate the "intent" into the exact native command you need.

```bash
# See all the cross-platform actions Phalanx understands
phalanx shell list-intents

# How do I check active network connections on this OS? (Returns netstat, ss, or Get-NetTCPConnection)
phalanx shell translate network_connections

# How do I flush the DNS cache natively?
phalanx shell translate flush_dns
```

Play around and see what works best for your learning style! The best way to learn is by doing, and Phalanx is here to help you experiment safely.
