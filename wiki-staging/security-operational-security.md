# 🥷 Operational Security (OPSEC)

Siyarix includes some basic `OPSECManager` and `StealthEngine` features to help configure your tools for quieter scans when doing authorized testing.

> [!IMPORTANT]
> These OPSEC features are meant for authorized engagements to avoid setting off noisy alerts while you work.

## 🛡️ Core OPSEC Controls

### 🧅 TOR Routing
You can route outbound Siyarix connections (including HTTP/HTTPS tool traffic) through TOR:

```bash
siyarix config set proxy socks5://127.0.0.1:9050
```

### 🔒 DNS over HTTPS (DoH)
To use encrypted DNS queries:

```bash
siyarix config set proxy dns+https://dns.cloudflare.com/dns-query
```

### ⏱️ Traffic Jitter
Add simple jitter to your requests:

```toml
[jitter]
enabled = true
min_delay = 1.0
max_delay = 5.0
```

### 🎭 User-Agent Rotation
Siyarix can cycle through browser profiles:

```toml
client_profile = "desktop_chrome"
# Other options: desktop_firefox, android_mobile, ios_safari
```

### 🐌 Request Pacing
Control your scanning speed to avoid tripping basic rate limits:

```toml
[pacing]
requests_per_second = 2.0
burst_size = 5
```

## 👻 The Stealth Engine (`stealth.py`)

The `StealthEngine` bundles these settings into easy "Evasion Levels".

| Level | Jitter | UA Rotation | DoH | Pacing |
|-------|--------|-------------|-----|--------|
| **None** | ❌ | ❌ | ❌ | ❌ |
| **Light** | ✅ | ✅ | ✅ | ✅ |
| **Medium**| ✅ | ✅ | ✅ | ✅ |
| **Heavy** | ✅ | ✅ | ✅ | ✅ |

### 🎯 Decoy Traffic
Siyarix can optionally generate background "noise" by browsing benign websites.

```toml
[decoy]
enabled = true
targets = ["https://example.com", "https://google.com"]
interval_seconds = 30
```

## 🔥 Session Burning

When you're done, you can clear your local session logs and history.

```bash
siyarix session-log --clear
```

## 📜 Audit Logging Note

> [!WARNING]
> While Siyarix attempts to be quiet on the network, **it logs your actions locally** in the audit log for your own accountability.

```bash
siyarix audit-log         # View your local audit trail
siyarix audit-log verify  # Verify log integrity
```
