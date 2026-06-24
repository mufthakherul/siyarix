# 🚑 Troubleshooting

Things don't always go according to plan, and that is okay! If you are running into issues with Siyarix, you have come to the right place. 

Below are the most common issues users face and the exact steps to fix them.

---

## 🛠️ Installation Issues

### I'm getting a `pip install` failure!
Siyarix requires some modern Python features. Ensure you are running the correct version:
```bash
# 1. Verify you are running Python 3.11 or newer
python --version                      

# 2. Upgrade your pip (outdated pip is the #1 cause of install failures)
pip install --upgrade pip

# 3. Try installing again with verbose output to see exactly where it fails
pip install siyarix -v                
```

### I'm seeing weird "Import Errors" when running Siyarix.
Sometimes, Python misses a dependency during a basic install. You can force it to pull down absolutely everything Siyarix needs by installing the `[all]` extra:
```bash
pip install "siyarix[all]"
```

### The terminal says `siyarix: command not found`.
Your operating system might not have Python's scripts folder added to your system `PATH`.
```bash
# Workaround: You can always run Siyarix directly as a Python module!
python -m siyarix --version           
```

---

## 🏃 Runtime & Execution Issues

### Error: "No AI provider available"
**The Cause:** Siyarix woke up, but it doesn't have a brain connected! You haven't provided any API keys, and there are no local AI engines running.
**The Fix:**
```bash
# Option A: Give it a cloud key
export OPENAI_API_KEY="sk-..."       

# Option B: Spin up a local, free AI engine
ollama pull llama3.1 && ollama serve 

# Option C: Run in Offline mode (no AI needed!)
siyarix --mode offline run "scan example.com"
```

### Error: "Connection Refused" or "Timeout"
**The Cause:** Siyarix cannot reach the AI provider's API endpoint.
**The Fix:**
```bash
# 1. Let Siyarix diagnose the connection for you
siyarix health                        

# 2. Are you stuck behind a corporate proxy? Check your proxy settings
siyarix config get proxy

# 3. If a proxy is misconfigured, clear it out
siyarix config set proxy ""
```

### Error: "Permission Denied"
**The Cause:** Security tools often need to craft raw network packets (like `nmap` doing OS fingerprinting). Standard users don't have the OS permissions to do this.
**The Fix:** Run Siyarix with elevated privileges! Use `sudo` on Linux/macOS, or open your terminal as an Administrator on Windows.

### "Tool Discovery Fails" / "Tool not found"
**The Cause:** Siyarix is trying to use a security tool (like `nmap`), but it isn't installed on your actual computer. Siyarix orchestrates tools; it doesn't bundle them all.
**The Fix:**
```bash
# Debian/Ubuntu Linux
sudo apt install nmap                

# macOS
brew install nmap                     

# Windows
winget install nmap                   

# Verify what Siyarix can see:
siyarix scan --list-tools             
```

---

## 🩺 Diagnosing Deeper Issues

### My Health Check shows "Degraded" or "Unhealthy"
If you run `siyarix health` and see red text, don't panic! The Health Checker breaks down exactly what is wrong. Look specifically at the components marked `DEGRADED` or `UNHEALTHY`—it will tell you if you are out of RAM, missing a tool, or failing to reach an API.

### Credential Store Errors
**The Cause:** Siyarix's encrypted vault might be corrupted, or your OS is missing the cryptography libraries needed to decrypt it.
**The Fix:**
```bash
# 1. Ensure the encryption dependency is fully installed
pip install cryptography              

# 2. Force Siyarix to re-initialize a fresh, healthy vault
siyarix init --force                  
```

---

## 🐛 Enabling Debug Mode

If the error messages aren't giving you enough context, you can turn on Debug Mode to see exactly what Siyarix is thinking under the hood.

```bash
# Enable it temporarily for a single session:
export SIYARIX_DEBUG=1
siyarix run "scan example.com"

# Or enable it permanently:
siyarix config set log_level debug
```

---

## ☢️ The Nuclear Option: Full Reset

If your configuration is completely tangled and you just want to start fresh:

```bash
# Option A: Just reset your settings back to factory defaults
siyarix config reset                  

# Option B: The Nuclear Option (Deletes history, credentials, cache, and settings)
rm -rf ~/.siyarix                     
```

---

## ⚠️ Known Limitations

Before pulling your hair out, ensure you aren't running into one of our known platform limitations:
- **Python 3.10 and older are NOT supported.** You must be on 3.11+.
- Windows raw sockets absolutely require Administrator privileges.
- Docker containers often lack native networking tools; you may need to install them inside the container.
- WSL2 (Windows Subsystem for Linux) network performance and bridging behaves differently than native Linux, which can affect scan accuracy.

---

## 📢 Still stuck? Reporting Issues

We are here to help! If you have found a bug, please let us know:

1. Enable debug logging: `export SIYARIX_DEBUG=1`
2. Run the diagnostic tool: `siyarix health`
3. Copy the output and open an issue on our [GitHub Repository](https://github.com/siyarix/siyarix/issues).

*Please be sure to include your OS, your Python version, and the full text of the error!*
