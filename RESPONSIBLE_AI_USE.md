# Responsible AI Use Policy

**Effective Date:** May 2026
**Version:** 1.0.0

Siyarix integrates artificial intelligence models to assist with cybersecurity tasks including planning, analysis, and automation. This policy outlines expectations, limitations, and responsibilities for all users of Siyarix's AI-powered features.

---

## 1. Core Principles

| Principle | Commitment |
|-----------|------------|
| **Human Oversight** | AI-assisted actions must be reviewable and overridable by human operators |
| **Transparency** | AI-generated outputs should be identifiable as such |
| **Safety** | Safety mechanisms must not be bypassable by default |
| **Privacy** | User data and targets must be protected from unnecessary exposure |
| **Accountability** | Human operators remain responsible for all actions taken through the platform |

---

## 2. Human Oversight Expectations

- AI-generated execution plans **must be reviewed** before execution in safety-critical contexts.
- Autonomous execution modes must have clearly documented limitations and escalation paths.
- The platform must provide mechanisms for users to pause, cancel, or override AI-generated actions.
- Users should understand the AI model's capabilities and limitations before relying on autonomous features.

---

## 3. Transparency Requirements

- AI-generated outputs (plans, commands, reports) should be clearly labeled as AI-assisted.
- The platform should indicate which AI model or provider generated a given output.
- Users should be informed when AI models are operating under reduced capability (fallback/heuristic mode).
- Modification history of AI-generated plans should be traceable.

---

## 4. Misuse Prevention

### 4.1 Prohibited AI-Assisted Activities

AI features of Siyarix must not be used to:

- Automate unauthorized access to systems
- Generate exploit code targeting unpatched vulnerabilities without authorization
- Automate social engineering or phishing campaigns
- Bypass human review or safety mechanisms intentionally
- Deceive individuals about the AI-assisted nature of interactions
- Process or exfiltrate personal data without legal basis
- Generate malware, ransomware, or other malicious payloads
- Conduct operations that would violate the [Ethical Use Policy](ETHICAL_USE.md)

### 4.2 Prompt Injection & Manipulation

Attempting to bypass or manipulate safety instructions embedded in AI system prompts is prohibited. This includes:

- Jailbreaking attempts targeting the AI planner
- Prompt injection to execute unauthorized commands
- Attempting to disable safety resolvers or masking engines

---

## 5. Autonomous Action Limitations

- Autonomous execution (no human-in-the-loop) should be limited to well-defined, low-risk operations.
- Destructive or disruptive operations should always require human approval.
- The platform should provide clear indication of autonomous mode status.
- Default configurations should favor safety over autonomy.

---

## 6. Hallucination Awareness

AI models may produce incorrect or dangerous outputs, including:

- Non-existent tool names or flags
- Incorrect command syntax
- Invalid IP addresses or network configurations
- Plausible-sounding but incorrect security analysis
- Dangerous command patterns that appear safe

Users must:

- Verify critical AI-generated commands before execution
- Test plans in dry-run mode when available
- Report persistent hallucination patterns to maintainers

---

## 7. Verification Requirements

Before executing AI-generated security operations:

1. Review the full execution plan
2. Verify target specifications are correct
3. Confirm safety resolver has analyzed the plan
4. Check that masking/redaction is active for cloud AI calls
5. Test on non-production systems when possible

---

## 8. Logging & Auditing

- AI-assisted actions should be logged with sufficient detail for post-event analysis.
- Audit logs should capture: prompt, generated plan, user modifications (if any), execution results.
- Logs should be tamper-evident where practical.
- Users should have access to their own AI interaction history.

---

## 9. Model Safety Considerations

- Users should be aware that AI providers may have their own data handling policies when using cloud models.
- Local/offline models are recommended for sensitive targets or air-gapped environments.
- The masking engine should be verified active before sending target data to cloud AI providers.
- API keys should be stored using the encrypted credential vault, not in plaintext configuration.

---

## 10. Data Privacy Expectations

- Target data sent to cloud AI providers is subject to that provider's privacy policy.
- Encrypted masking should be used when processing sensitive targets.
- Session data stored locally should be protected at rest.
- Users should minimize sharing of personal or sensitive data in AI prompts.

---

## 11. Responsible Automation

- Automated security operations should include circuit breakers and rate limiting.
- Recurring automated scans should not overwhelm target systems.
- Distributed or parallel execution should respect target capacity.
- Scheduled operations should include notification mechanisms.

---

## 12. Compliance & Governance

Organizations deploying Siyarix's AI features should:

- Assess compliance with applicable AI regulations (EU AI Act, etc.)
- Maintain documentation of AI system deployment and configuration
- Conduct periodic reviews of AI-assisted security operations
- Train operators on responsible AI use and platform safety features

---

*This policy supplements the GNU Affero General Public License v3.0 and the [Ethical Use Policy](ETHICAL_USE.md). It is intended as a governance framework, not legal advice. Consult qualified professionals for regulatory compliance guidance.*
