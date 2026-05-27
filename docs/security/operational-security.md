# Operational Security

Siyarix provides operational security (OPSEC) controls for conducting assessments with reduced detectability.

## OPSEC controls

### TOR routing

Route outbound connections through TOR:

```bash
siyarix config set proxy socks5://127.0.0.1:9050
```

All HTTP/HTTPS traffic from tools and AI provider calls will route through TOR.

### DNS over HTTPS

Prevent DNS leakage:

```bash
siyarix config set proxy dns+https://dns.cloudflare.com/dns-query
```

DNS queries use encrypted HTTPS instead of plain UDP.

### Traffic jitter

Random delays between requests to avoid pattern detection:

```toml
# settings.toml
[jitter]
enabled = true
min_delay = 1.0
max_delay = 5.0
```

### User-Agent rotation

Rotate HTTP User-Agent headers:

```toml
# settings.toml
client_profile = "desktop_chrome"
# Options: desktop_chrome, desktop_firefox, android_mobile, ios_safari
```

### Proxy rotation

Rotate through a pool of proxies:

```toml
# settings.toml
proxy_pool = "http://proxy1:8080,http://proxy2:8080,http://proxy3:8080"
```

Each connection picks a random proxy from the pool.

## Stealth engine (`stealth.py`)

The `StealthEngine` manages evasion levels:

```python
class StealthConfig:
    level: str  # none, light, medium, heavy
    use_tor: bool
    use_proxy_chain: bool
    jitter_enabled: bool
    user_agent_rotation: bool
    dns_over_https: bool
```

### Evasion levels

| Level | TOR | Jitter | Proxy rotation | UA rotation | DoH |
|-------|-----|--------|----------------|-------------|-----|
| none | No | No | No | No | No |
| light | No | Yes | No | Yes | Yes |
| medium | Yes | Yes | Yes | Yes | Yes |
| heavy | Yes | Yes | Yes | Yes | Yes (+ random delays 5-15s) |

## Session burning

After completing an assessment:

```bash
siyarix session-log --clear
```

Clears:

- Command history
- Knowledge graph
- Tool outputs
- Session logs (if configured)

## Audit logging

All actions are logged regardless of OPSEC settings. The audit log is tamper-evident:

```bash
siyarix audit-log  # View audit trail
```

## Red team simulation safety

When conducting red team exercises:

1. Define the rules of engagement in a workflow file
2. Use persona `pentester` for standard assessment rules
3. Enable safe mode for initial reconnaissance
4. Use kill switch for emergency stop
5. Log all actions to the audit trail
6. Generate comprehensive report after completion

## Recommended configuration for assessments

```toml
# settings.toml
stealth_mode = true
proxy_pool = "socks5://127.0.0.1:9050,socks5://127.0.0.1:9051"
client_profile = "desktop_chrome"
tls_verify = true
default_output_format = "json"
scan_timeout = 600
```
