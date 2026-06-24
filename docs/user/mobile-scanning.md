# 📱 Mobile Application Scanning

Mobile apps often carry the keys to your kingdom. Siyarix is building a dedicated mobile scanning engine to help you tear down APKs and IPAs, hunting for dangerous permissions, insecure flags, and hardcoded secrets.

> [!WARNING]
> **Active Development Notice**: The mobile application security scanner is currently under active development. A `MobileScanner` stub exists, and the full analysis pipeline is being built.

---

## 🚧 Current Status

Currently, the `MobileScanner` class acts as a placeholder. You can feed it an app package, but it doesn't perform actual decompilation or analysis yet.

```python
from siyarix.chat.stubs import MobileScanner

scanner = MobileScanner()

# This is a stub! It currently returns an empty dictionary {}.
result = scanner.scan_apk("app.apk")
```

---

## 🔮 Planned Capabilities

Our roadmap for mobile security is extensive. Here is what Siyarix will soon be able to do:

### 🤖 Android APK Analysis
- **Dangerous Permissions**: Detecting apps that ask for too much (e.g., unnecessary access to Location, Camera, or SMS).
- **Insecure Flags**: Flagging risky Android manifest settings like `allowBackup="true"`, `debuggable="true"`, or `usesCleartextTraffic="true"`.
- **Hardcoded Secrets**: Automatically decompiling the APK to hunt down API keys, tokens, and passwords buried in the code.
- **Manifest Analysis**: Mapping out exported components, intent filters, and the app's overall attack surface.

### 🍏 iOS IPA Analysis
- **Plist Inspection**: Scanning `Info.plist` files for sensitive configuration data.
- **Binary Analysis**: Checking the compiled binary for modern security protections (PIE, ARC, stack canaries).
- **Entitlement Review**: Identifying over-provisioned app capabilities.

### 🕵️ Dynamic Analysis (Future Roadmap)
- **Network Interception**: Automatically proxying traffic to detect cleartext communication and weak TLS configurations.
- **Runtime Injection**: Testing how the app handles common memory manipulation techniques.
- **Data Storage Analysis**: Inspecting local databases and file systems for insecurely stored data.

---

## 📣 Stay Tuned!

The mobile scanning module will bring massive value to developers and security researchers alike. We will provide updates on platform support and feature availability as the development progresses!
