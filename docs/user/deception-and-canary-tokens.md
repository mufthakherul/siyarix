> [!NOTE]
> 👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. The feature described on this page is currently **Planned / Under Development** and may not be fully functional in the codebase yet. Stay tuned for updates! 🚀

# 🪤 Deception Technology & Canary Tokens

Catch attackers in the act! Deception technology flips the script, allowing you to lay traps for malicious actors inside your network. 

> [!WARNING]
> **Active Development Notice**: Siyarix's deception capabilities are currently under heavy construction! A `CanaryTokenManager` stub exists, and we are working hard on the full implementation, which will include honeypots, canary tokens, and trapdoor credentials.

---

## 🚧 Current Status

Right now, the `CanaryTokenManager` class is acting as a placeholder in the codebase. You can call the commands, but they will currently return empty results while we finish building the engine.

```python
from siyarix.chat.stubs import CanaryTokenManager, CanaryTokenType

manager = CanaryTokenManager()

# This is a stub! It currently returns None.
manager.deploy_to_target("webapp.example.com", [CanaryTokenType.WEB])

# This is a stub! It currently returns an empty list [].
tokens = manager.list_tokens()
```

---

## 🔮 Planned Capabilities

We are building a robust suite of deception tools. Here is what you can expect in upcoming releases:

### 🐤 Canary Tokens

Canary tokens are fake digital assets. When an attacker touches them, you get an immediate, high-fidelity alert.

| Token Type | How It Traps Attackers | Where We Deploy It |
|------------|------------------------|--------------------|
| **WEB** | A unique URL that triggers an alert the moment it's requested. | Web access logs, emails |
| **DNS** *(planned)* | A unique DNS name that alerts you when someone tries to resolve it. | DNS zone files |
| **AWS Key** *(planned)* | A fake AWS credential that screams if someone tries to use it. | Config files, GitHub |
| **Credential** *(planned)* | A juicy-looking username and password pair. | Credential stores, memory |
| **File** *(planned)* | A document that alerts you the second it is opened. | Desktop, shared drives |
| **DB Record** *(planned)* | A fake database entry that triggers when queried. | Production databases |
| **API Key** *(planned)* | A decoy API key waiting to be scraped. | Config files, source code |

### 🍯 Honeypot Detection (Planned)

Want to know if you're exploring a real system or a trap? Siyarix will be able to detect known honeypots:
- **Signature Analysis**: Identifying common honeypots like Cowrie, Dionaea, Honeyd, and T-Pot.
- **Banner Analysis**: Checking SSH banners for deceptive patterns.
- **Fingerprinting**: Analyzing HTTP responses and service behaviors for anomalies.

### 🎭 Fake Banners (Planned)

Confuse attackers by making your systems look like something else!
- Deploy highly realistic decoy banners for SSH, HTTP, FTP, etc.
- Customize service fingerprints to waste attackers' time.
- Fully automated deployment across your decoy infrastructure.

### 🚪 Trapdoor Credentials (Planned)

- Generate fake credentials that exist solely to trigger alarms when used.
- Seamless integration with your existing credential stores.
- Instant alert routing directly to your security team.

---

## 📣 Stay Tuned!

We are incredibly excited about the deception technology suite. We are actively developing these features and will share updates and release timelines as soon as they are ready!
