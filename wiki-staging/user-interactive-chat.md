# 💬 Interactive Chat (REPL)

Welcome to the beating heart of Siyarix! 

While you can certainly run Siyarix commands one-by-one from your standard terminal, the true power of the platform unlocks when you enter the **Interactive Chat Mode** (also known as the REPL - Read-Eval-Print Loop). 

Think of it as a dedicated, context-aware command center where you and your AI co-pilot work together to hunt down vulnerabilities.

---

## 🚀 Launching the Chat

Getting in is easy. Just type the main command with no arguments:

```bash
siyarix
```

Instantly, you will be dropped into a beautiful, `prompt_toolkit`-powered shell.

---

## 🗣️ Natural Language Execution

Once inside, you don't need to memorize obscure flags. You can literally just talk to Siyarix:

```text
> scan 192.168.1.1
> find all open ports on example.com
> run a vulnerability scan against the web server
> what tools do I have available?
```

The AI engine automatically intercepts your natural language, interprets your intent, builds an execution plan, and runs the necessary tools behind the scenes.

---

## 🪄 The Magic of SmartAutocomplete

We hate typing out long IP addresses and file paths just as much as you do. The REPL comes equipped with **SmartAutocomplete**:

- Hit `Tab` to autocomplete commands, target IPs, and file paths.
- Siyarix remembers your conversation history and provides **context-aware suggestions**.
- Type `/` to instantly see a dropdown list of every available slash command.

---

## 🪟 Split-Pane Layout

Want to keep an eye on the logs while you chat? Siyarix supports a gorgeous vertical split-pane view. 

Just type `/split` in the chat!

- **Left Pane:** Your input area and conversation history.
- **Right Pane:** Live output, raw logs, or status information.

*Pro-Tip: You can change what the right pane shows! Try typing `/split timeline`, `/split metrics`, or `/split attack_map`.*

---

## 🗃️ Session Management & Memory

Siyarix doesn't suffer from amnesia. Your entire session is seamlessly persisted to a local SQLite database (`~/.siyarix/sessions.db`). 

This means Siyarix remembers:
- The exact commands you ran and when you ran them.
- Your entire multi-turn conversation with the AI.
- The findings and results of previous scans (so it can use them as context for future commands!).

Want to pick up where you left off tomorrow? You can resume any session perfectly.

---

## ⌨️ Keyboard Shortcuts

Navigate the REPL like a pro with these hotkeys:

| Shortcut | What it does |
|----------|--------|
| `Tab` | Triggers the Smart Auto-complete |
| `Up` / `Down` | Navigate through your command history |
| `Ctrl+C` | Cancels whatever tool is currently running |
| `Ctrl+L` | Clears the screen to keep things tidy |
| `Ctrl+D` | Exits the REPL cleanly |

---

## 📜 The Slash Command Reference

If you want to bypass natural language and issue direct commands to the Siyarix engine, use slash commands. Siyarix boasts over **54+ slash commands** for total control.

*(Don't try to memorize these! Just type `/` in the REPL and hit `Tab` to see them all.)*

### Core Controls
| Command | Description |
|---------|-------------|
| `/help` | Show all slash commands (or `/help <cmd>` for details) |
| `/exit` | Exit the session |
| `/clear` | Clear the terminal screen |
| `/new` | Start a brand new, clean conversation thread |
| `/history`| Show your command history |

### AI & Persona Management
| Command | Description |
|---------|-------------|
| `/persona`| Switch the AI's mindset (e.g., to Red Team or Blue Team) |
| `/model` | Switch the AI provider model on the fly |
| `/provider`| See or switch your active AI provider |
| `/agent` | Launch an autonomous agent to achieve a goal |

### Security Operations
| Command | Description |
|---------|-------------|
| `/scan` | Run a quick scan directly from the chat |
| `/target` | Set or show the current default target IP/URL |
| `/tools` | List all available security tools from the registry |
| `/opsec` | Run operational security checks on your environment |
| `/stealth`| Toggle OPSEC stealth mode on or off |
| `/report` | Generate an assessment report of your current findings |
| `/diff` | Compare the results of two different scans |

### Customization & State
| Command | Description |
|---------|-------------|
| `/theme` | Change the terminal color theme |
| `/split` | Toggle the split-pane layout |
| `/config` | View or change configuration settings |
| `/key` | Set or rotate your encrypted API keys |
| `/save` | Manually save the current session state |
| `/load` | Load a previously saved session |

---

## ⏭️ Next Steps

You are now a master of the CLI and the REPL. 

Ready to put it all together? Check out the **[Security Workflows](user-security-workflows)** guide to see how Siyarix handles real-world penetration testing and incident response scenarios!
