# Deception & Canary Tokens

Siyarix provides deception capabilities for detecting unauthorized access and gathering threat intelligence.

## Honeypot detection

The `HoneypotDetector` identifies known honeypots by matching service banners against 9 signatures.

### Detected honeypots

| Signature | Type | Detection pattern |
|-----------|------|-------------------|
| Cowrie SSH | SSH honeypot | SSH banner contains "cowrie" |
| Dionaea | Malware honeypot | SIP banner contains "Dionaea" |
| Honeyd | Virtual honeypot | Banner says "Honeyd Virtual" |
| Glastopf | Web honeypot | Response contains "Glastopf" |
| T-Pot | Honeypot platform | Banner contains "T-Pot" |
| MHN | Modern Honeypot Network | Server identifies as MHN |
| Nmap honeypot | Scan detection | Nmap output pattern match |
| Canary tokens | Token detection | Known canary token patterns |
| Custom | User-defined | Configurable signatures |

### Usage

```bash
# Detect honeypots during scan
siyarix run "check if target is running honeypot services"

# The detector checks: SSH banners, HTTP responses, service fingerprints
```

## Canary tokens

Canary tokens are deception artifacts that trigger alerts when accessed.

### Token types

| Type | Description | Deployment |
|------|-------------|------------|
| Web | URL that alerts on request | Drop in web access logs |
| DNS | DNS name that alerts on resolution | Add to DNS zone |
| AWS Key | Fake AWS credential that alerts on use | Place in config files |
| Credential | Fake username/password pair | Add to credential store |
| File | File that alerts on open | Place on filesystem |
| DB Record | Database record that alerts on query | Insert into table |
| API Key | Fake API key that alerts on use | Place in config/code |

### Creating tokens

```bash
# Create a web canary token
siyarix run "deploy a web canary token at /admin/backup"

# Create a credential token
siyarix run "add a fake AWS key to the config files"
```

### Management

```python
manager = CanaryTokenManager()
token = manager.create_token(
    token_type=CanaryTokenType.WEB,
    location="https://target.com/admin/",
    description="Detects admin panel access"
)
manager.deploy(token)
```

### Alert handling

When a token is triggered:

1. Alert handler callback fires
2. Event is logged to the audit log
3. Notification is sent (if configured)
4. Token state changes to triggered

## Fake banners

The `FakeBannerGenerator` creates realistic decoy banners:

```python
generator = FakeBannerGenerator()
ssh_banner = generator.generate_banner("ssh")     # "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
http_banner = generator.generate_banner("http")   # "Apache/2.4.41 (Ubuntu)"
ftp_banner = generator.generate_banner("ftp")     # "220 vsFTPd 3.0.3"
```

## Trapdoor credentials

Trapdoor credentials are fake entries in the credential store that trigger alerts when used:

```python
manager = TrapdoorCredentialManager()
manager.add_trapdoor("admin", "fake_password_hash")
# If someone tries these credentials, an alert fires
```

## Use cases

- **Detection**: Identify when an attacker has accessed a decoy resource
- **Attribution**: Track attacker behavior through token access patterns
- **Deterrence**: Make reconnaissance more costly for attackers
- **Intelligence**: Gather information about attacker TTPs
