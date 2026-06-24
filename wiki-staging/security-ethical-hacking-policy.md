# ⚖️ Ethical Hacking Policy

Siyarix is a cybersecurity orchestration tool. While it's a personal project, it's powerful, and I want to be clear about the boundaries for its ethical and legal use. 

> [!CAUTION]
> **Please read this carefully.** By using Siyarix, you agree to adhere to these guidelines.

## ✅ Authorized Use

Siyarix is built for defense, learning, and authorized testing. You may **only** use Siyarix against systems that you own or have explicit authorization to assess. 

**Acceptable use cases include:**
- **Your Own Infrastructure:** Systems and networks you own.
- **Authorized Penetration Tests:** Client systems covered by a legally binding agreement.
- **Bug Bounty Programs:** Acting strictly within their published rules.
- **Educational Labs:** Platforms like HackTheBox or TryHackMe.
- **Compliance Validation:** Automated checks on authorized networks.

## 🚫 Prohibited Use

Siyarix is **not** a tool for malicious actors. The following are strictly prohibited:

- ❌ Testing or scanning systems without explicit authorization.
- ❌ Launching Denial-of-Service (DoS) or DDoS attacks.
- ❌ Exfiltrating data beyond an authorized scope.
- ❌ Modifying or destroying data without permission.
- ❌ Any activity violating local computer misuse laws.

> [!IMPORTANT]
> Siyarix must **never** be integrated with kinetic platforms or used maliciously.

## 📜 Rules of Engagement

When testing legally:
1. **Define the Scope:** Know what is "in scope".
2. **Start Safe:** Try Safe Mode (`SIYARIX_SAFE_MODE=1`) for initial reconnaissance.
3. **Protect Data:** Rely on the DLP engine to protect sensitive data.
4. **Least Privilege:** Use the quietest techniques necessary.

## 🌍 Legal Compliance

You are responsible for complying with the laws of your jurisdiction and your targets (e.g., CFAA in the US, Computer Misuse Act in the UK).

## 🦺 Safe Mode

When in doubt, use Safe Mode. It restricts Siyarix to reconnaissance.

```bash
export SIYARIX_SAFE_MODE=1
siyarix scan quick target.com
```

## 🗣️ Responsible Disclosure

If you find a vulnerability using Siyarix on an authorized target:
- Report it privately to the vendor.
- Give them reasonable time to patch it.
- **Never** publicly dump vulnerability data maliciously.

## 🚩 Reporting Misuse

If you discover someone using Siyarix maliciously or find a bug in Siyarix itself, please let me know via GitHub Security Advisories or by opening an issue!
