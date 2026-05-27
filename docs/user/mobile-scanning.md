# Mobile Application Scanning

Siyarix includes a built-in mobile application security scanner for Android APK analysis.

## Android APK analysis

```bash
# Scan an APK file
siyarix run "scan mobile app app.apk for security issues"
```

### What is checked

The scanner decompiles the APK and checks for:

#### Dangerous permissions (13 checks)

| Permission | Risk |
|------------|------|
| `READ_CONTACTS` | Access to contact data |
| `ACCESS_FINE_LOCATION` | Precise GPS location |
| `RECORD_AUDIO` | Microphone access |
| `CAMERA` | Camera access |
| `READ_SMS` | SMS message access |
| `SEND_SMS` | Send SMS without user awareness |
| `READ_CALL_LOG` | Call history access |
| `PROCESS_OUTGOING_CALLS` | Monitor outgoing calls |
| `BIND_ACCESSIBILITY_SERVICE` | UI event monitoring |
| `SYSTEM_ALERT_WINDOW` | Overlay attacks (tapjacking) |
| `REQUEST_INSTALL_PACKAGES` | Side-loading APKs |
| `INTERNET` + `READ_EXTERNAL_STORAGE` | Data exfiltration risk |
| `BIND_NOTIFICATION_LISTENER_SERVICE` | Read notifications |

#### Insecure flags (5 checks)

| Flag | Issue |
|------|-------|
| `allowBackup=true` | App data can be backed up (data theft risk) |
| `debuggable=true` | Debug mode enabled in production |
| `exported=true` (no permission) | Activity/service exposed without protection |
| `usesCleartextTraffic=true` | HTTP traffic allowed (no TLS) |
| `testOnly=true` | Test mode enabled |

#### Hardcoded secrets (6 patterns across XML, JSON, Java, Kotlin, Smali)

- API keys, passwords, tokens
- AWS access keys
- OpenAI API keys
- JWT tokens
- Private keys

### Output

```json
{
  "package_name": "com.example.app",
  "version": "2.1.0",
  "min_sdk": "24",
  "target_sdk": "34",
  "permissions": ["ACCESS_FINE_LOCATION", "CAMERA", ...],
  "findings": [
    {
      "severity": "high",
      "category": "dangerous_permission",
      "message": "App requests CAMERA permission without clear use"
    }
  ]
}
```

### Report

Generate a mobile security report:

```bash
siyarix report generate --include mobile
```
