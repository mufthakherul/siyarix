# Responsible AI Use Policy

**Effective Date:** June 2026
**Version:** 1.0.1
**Applies to:** All AI-powered features of Siyarix v1.0.1

Siyarix integrates artificial intelligence models from multiple providers to assist with cybersecurity tasks including planning, analysis, code generation, and automation. This policy defines the principles, expectations, limitations, and responsibilities governing the use of Siyarix's AI-powered features.

---

## 1. Core Principles

| Principle | Commitment |
|-----------|------------|
| **Human Oversight** | AI-assisted actions must be reviewable, understandable, and overridable by human operators at all times |
| **Transparency** | AI-generated outputs must be clearly identifiable as such, including which model or provider generated them |
| **Safety** | Safety mechanisms (Permission Gate, Masking Engine, Danger Analysis) must not be bypassable through default configuration |
| **Privacy** | User data, target information, and credentials must be protected from unnecessary exposure to AI providers |
| **Accountability** | Human operators remain fully responsible for all actions taken through the platform, including AI-assisted actions |
| **Fairness** | AI models should be used in ways that do not discriminate against or harm protected groups or individuals |
| **Reliability** | AI features should degrade gracefully when models are unavailable or produce unreliable outputs |

---

## 2. Human Oversight

- AI-generated execution plans **must be reviewed** before execution in safety-critical contexts
- The Permission Gate provides two-stage danger analysis that cannot be permanently disabled through standard configuration
- Autonomous execution modes have clearly documented limitations and escalation paths to human operators
- The platform provides mechanisms to pause, cancel, modify, or override AI-generated actions at every stage
- Users should understand the capabilities, limitations, and failure modes of the AI model they are using before relying on autonomous features

### Oversight Tiers by Mode

| Mode | AI Autonomy | Human Oversight Required |
|------|-------------|--------------------------|
| **REGISTRY** | Tool execution with AI context | Command review recommended |
| **INTERACTIVE** | AI-assisted planning | Step-by-step approval |
| **HYBRID** | AI proposes actions | Human approval for destructive operations |
| **AUTONOMOUS** | Goal-driven closed loop | Configuration limits and circuit breakers apply |

---

## 3. Transparency

- AI-generated outputs (plans, commands, analysis, reports) are clearly labeled as AI-assisted
- The platform indicates which AI model or provider generated each output
- Users are notified when AI models operate under reduced capability (fallback to heuristic/offline mode)
- Modification history of AI-generated plans is traceable through the session audit log
- AI system prompts and safety instructions are documented in the project source code

---

## 4. Misuse Prevention

### 4.1 Prohibited AI-Assisted Activities

AI features of Siyarix must not be used to:

- Automate unauthorized access to systems or networks
- Generate exploit code targeting unpatched vulnerabilities without prior authorization
- Automate social engineering, phishing, or vishing campaigns
- Intentionally bypass human review or safety mechanisms
- Deceive individuals about the AI-assisted nature of interactions or outputs
- Process, exfiltrate, or store personal data without legal basis or authorization
- Generate malware, ransomware, worms, trojans, or other malicious payloads
- Conduct operations that would violate the [Ethical Use Policy](ETHICAL_USE.md)
- Automate attacks against critical infrastructure without lawful mandate

### 4.2 Prompt Injection & Safety Boundary Violations

Attempting to bypass, manipulate, or disable safety mechanisms embedded in AI system prompts or the platform's safety layer is prohibited. This includes:

- Jailbreaking, prompt injection, or adversarial prompt attempts targeting the AI planner
- Crafting inputs designed to bypass the Permission Gate or Danger Analysis
- Attempting to disable the Safety Resolver, Masking Engine, or other safety components
- Deliberately providing misleading context to elicit unauthorized actions from the AI

---

## 5. Autonomous Action Limitations

- Autonomous execution (no human-in-the-loop approval) is limited to well-defined, low-risk, non-destructive operations by default
- Destructive or disruptive operations (system modification, data deletion, service interruption) always require human approval
- The platform provides clear visual indication of autonomous mode status during operation
- Default configurations favor safety over autonomy -- users must explicitly enable higher-risk modes
- Autonomous execution includes configurable circuit breakers: max steps, max duration, rate limits, and failure thresholds
- Scheduled recurring autonomous operations include notification and escalation mechanisms

---

## 6. Hallucination & Error Awareness

AI models may produce incorrect, nonsensical, or dangerous outputs, including:

- Non-existent tool names, command-line flags, or invocation patterns
- Incorrect command syntax for real tools
- Invalid IP addresses, network ranges, or system configurations
- Plausible-sounding but factually incorrect security analysis
- Dangerous command patterns that appear benign to non-experts
- Misidentified software versions, CVEs, or vulnerability classifications
- Incorrect or hallucinated compliance requirements or regulatory citations

### User Obligations

- Verify critical AI-generated commands in a safe environment before execution
- Test plans using dry-run or review modes when available
- Cross-reference AI-generated findings with manual verification where possible
- Report persistent hallucination patterns or consistent errors to project maintainers
- Never assume AI-generated security advice is correct without verification

---

## 7. Pre-Execution Verification Checklist

Before executing AI-generated security operations, verify:

1. The full execution plan has been reviewed and understood
2. Target specifications (IPs, domains, ports, paths) are correct and within authorized scope
3. The Permission Gate has analyzed the plan and issued a risk assessment
4. The Masking Engine is active for cloud AI provider interactions
5. Destructive operations have been explicitly approved (if applicable)
6. A backup or recovery plan exists for target systems
7. The operation is within the authorized scope of testing

---

## 8. Logging & Auditing

- All AI-assisted actions are logged with sufficient detail for post-event analysis and incident response
- Audit logs capture: prompt summary, generated plan, user modifications, execution results, and provider information
- Full AI prompts and responses are not stored in logs by default (debug logging may capture them for troubleshooting)
- Audit log entries are tamper-evident through cryptographic chaining (SHA-256)
- Users can access their own AI interaction history through session logs
- Provider selection and failover events are recorded with cause and resolution

---

## 9. Model Safety Considerations

- Users should be aware that cloud AI providers have their own data handling, privacy, and retention policies
- Local/offline models (Ollama, LM Studio, llama.cpp, vLLM, LocalAI) are strongly recommended for:
  - Classified or sensitive target environments
  - Air-gapped networks without external connectivity
  - Operations subject to GDPR/CCPA data processing restrictions
  - Internal corporate networks with data export prohibitions
- The Masking Engine automatically redacts IPs, domains, credentials, and custom patterns before sending data to cloud providers
- API keys are stored using AES-256-GCM encrypted credential vault, not in plaintext configuration

---

## 10. Data Privacy

- Target data sent to cloud AI providers is subject to that provider's privacy policy and terms of service
- The bidirectional masking engine should be verified active before sending target data to cloud AI providers
- Session data stored locally (`~/.siyarix/`) is protected at rest
- Users should minimize sharing of personal data, credentials, or sensitive information in AI prompts
- When using cloud AI providers, assume data is processed in jurisdictions where the provider operates

---

## 11. Responsible Automation

- Automated security operations must include circuit breakers: max execution time, max steps, rate limits
- Recurring automated scans and operations must not overwhelm target systems or networks
- Distributed or parallel execution modes must respect target capacity and network constraints
- Scheduled operations should include pre-execution notifications and post-execution summaries
- Automated operations should implement exponential backoff and retry limits

---

## 12. Compliance & Governance

Organizations deploying Siyarix's AI features should:

- Assess compliance with applicable AI regulations (EU AI Act, proposed U.S. AI frameworks, sector-specific AI rules)
- Maintain documentation of AI system deployment, configuration, and model selection
- Conduct periodic reviews of AI-assisted security operations and safety mechanism effectiveness
- Train operators on responsible AI use, platform safety features, and AI limitation awareness
- Establish incident response procedures for AI-related failures or safety boundary violations
- Review AI provider terms of service for data handling, model usage restrictions, and liability limitations

---

*This policy supplements the GNU Affero General Public License v3.0 or later and the [Ethical Use Policy](ETHICAL_USE.md). It is intended as a governance framework and best-practice guidance, not legal advice. Consult qualified professionals for regulatory compliance guidance specific to your organization and jurisdiction.*

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
