# Troubleshooting

## Installation issues

### `pip install` fails

```bash
# Ensure Python 3.11+
python --version

# Upgrade pip
pip install --upgrade pip

# Try with verbose output
pip install siyarix -v
```

### Import errors

```bash
# Ensure all dependencies are installed
pip install "siyarix[all]"
```

### `siyarix: command not found`

```bash
# Check if Python scripts directory is on PATH
python -m siyarix --version

# Find the script location
which siyarix  # Linux/macOS
where siyarix  # Windows
```

## Runtime issues

### "No AI provider available"

```
Error: No AI provider available
```

**Cause**: No API keys set and no local provider running.

**Fix**: Set at least one API key or start a local provider:

```bash
# Option 1: Set an API key
export OPENAI_API_KEY="sk-..."

# Option 2: Start Ollama
ollama pull llama3.1
ollama serve

# Option 3: Start LM Studio and enable API server on port 1234
```

### Connection errors

```
ProviderError: Connection refused
```

**Cause**: Provider endpoint unreachable.

**Fix**: Check network, proxy settings, and provider URL:

```bash
siyarix config get proxy
siyarix config set proxy ""
```

### "Permission denied"

```
PermissionError: [Errno 13] Permission denied
```

**Cause**: Running without necessary permissions for the target operation.

**Fix**: Use sudo (Linux/macOS) or run as Administrator (Windows) when scanning local network interfaces or using raw sockets.

### Tool discovery fails

```
Warning: No security tools found
```

**Cause**: Common security tools are not on PATH.

**Fix**: Install tools or verify PATH:

```bash
# Install nmap
sudo apt install nmap   # Debian/Ubuntu
brew install nmap        # macOS
winget install nmap       # Windows

# Check tool registry
siyarix scan --list-tools
```

## Debug mode

Enable verbose logging:

```bash
export SIYARIX_DEBUG=1
siyarix ...
```

Or set log level:

```bash
siyarix config set log_level debug
```

## Reset everything

```bash
# Reset configuration to defaults
siyarix config reset

# Full reset (removes settings, history, cache)
rm -rf ~/.siyarix
```

## Known limitations

- **Python 3.11+ required** — older versions are not supported
- **Windows raw sockets**: require Administrator privileges for certain scan types
- **Docker**: some tools may not be available in containerized environments
- **WSL2**: network performance may differ from native Linux

## Reporting issues

If problems persist:

1. Run with debug logging: `export SIYARIX_DEBUG=1`
2. Collect logs: `siyarix health`
3. Open an issue at: https://github.com/mufthakherul/siyarix/issues

Include Python version, OS, and the full error output.

## Getting help

```bash
siyarix --help
siyarix <command> --help   # Command-specific help
```

Inside interactive chat: `/help` lists all slash commands.
