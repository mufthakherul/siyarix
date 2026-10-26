# 🥷 Operational Security (OPSEC)

Siyarix exposes two related surfaces: **`OPSECManager`** (`opsec.py`) for session markers / memory-only / burn, and **`StealthEngine`** (`stealth.py`) for User-Agent rotation and request jitter.

!!! info
    These controls are for **authorized** engagements. Network isolation claims (Tor circuits, DoH resolvers, MAC randomization, OS netns) via `OPSECManager.isolate()` are **not implemented**.

## 🛡️ OPSECManager (`opsec.py`) — what actually works

### ✅ Implemented: `memory_only`

```text
/opsec isolate [--target <host>]
```

Enables in-process suppression of persistent audit/cache writes. Soft session labels are markers only — `isolated` remains `False` (no OS network namespace).

!!! warning "Accountability loss"
    `memory_only` discards unflushed audit events. Tamper-evident accountability for that session is **lost**. Do not enable when attestability or compliance evidence is required.

### ✅ Implemented: session burn (local files only)

```text
/opsec burn [session_id]
```

Performs a **3-pass random overwrite** of session files under the config log directory. OS memory zeroization, swap/pagefile wipe, disk-cache flush, and network-trace clearing are **`not_implemented`**. Burn reports **partial** status — success applies only to the local shred path.

### ❌ Planned / not implemented via `isolate()`

| Control | Status |
|---------|--------|
| OS network namespace | Planned |
| Tor routing | Planned |
| DNS-over-HTTPS (DoH) | Planned |
| MAC randomization | Planned |

Requesting Tor/DoH/MAC returns `success=False` and leaves those status flags off.

## 🥷 StealthEngine (`stealth.py`) — UA & jitter

| Level | Jitter % | UA rotation | Proxy-chain flag | Decoy flag |
|-------|----------|-------------|------------------|------------|
| **none** | 0 | ❌ | ❌ | ❌ |
| **light** | 10 | ✅ | ❌ | ❌ |
| **medium** | 30 | ✅ | ✅ | ❌ |
| **heavy** | 50 | ✅ | ✅ | ✅ |
| **paranoid** | 80 | ✅ | ✅ | ✅ |

- **Implemented:** User-Agent pool rotation and jittered delays.
- **Config markers only:** proxy-chain / decoy flags may inject localhost proxy env defaults (`127.0.0.1:9050`, `8118`). Verify your local listener; this is **not** OPSECManager Tor/DoH isolation.

Optional proxy via normal config (separate from `isolate()`):

```bash
siyarix config set proxy socks5://127.0.0.1:9050
```

## 📜 Audit Logging Note

!!! warning
    By default Siyarix **persists** a local audit trail for accountability. `memory_only` intentionally turns that off for the session.

```bash
siyarix audit-log         # View your local audit trail
siyarix audit-log verify  # Verify log integrity
```
