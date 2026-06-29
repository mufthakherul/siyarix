# Siyarix Ethical Use Policy

**Effective Date:** June 2026
**Version:** 1.0.0
**Applies to:** Siyarix v1.0.0 and all derivative works

Siyarix is an AI-powered cybersecurity orchestration platform designed to enhance defensive security operations and authorized security testing capabilities. This policy defines acceptable and prohibited uses of the Siyarix platform, its components, and any modified or derivative versions.

This policy applies to all users, contributors, distributors, integrators, and operators of Siyarix, including those deploying modified versions or services built upon the platform.

---

## 1. Permitted Use

You are authorized to use Siyarix for the following purposes, provided all applicable laws, regulations, and contractual obligations are observed:

| Category | Examples |
|----------|----------|
| **Authorized Security Testing** | Penetration tests, vulnerability assessments, red-team and purple-team exercises conducted with explicit written authorization from the system owner |
| **Defensive Security** | Internal network monitoring, incident response and forensics, security hardening, configuration auditing, compliance validation |
| **Educational & Research** | Academic study, cybersecurity curriculum delivery, capture-the-flag (CTF) events, controlled lab environments, security research |
| **Bug Bounty Programs** | Testing within the explicit scope of publicly disclosed bug bounty or vulnerability disclosure programs |
| **Malware Analysis** | Reverse engineering, dynamic analysis, and detonation of malware in isolated, air-gapped sandbox environments |
| **Personal Development** | Self-education in cybersecurity concepts, tool orchestration, AI-assisted security workflows, and defensive techniques |
| **Enterprise Security Operations** | Security assessments of systems, networks, applications, and infrastructure that you own or are explicitly authorized to test |
| **Supply Chain Security** | Software composition analysis, dependency auditing, and infrastructure-as-code security scanning of systems you own or operate |
| **Compliance Validation** | Automated compliance checks against regulatory frameworks (PCI-DSS, HIPAA, SOC 2, ISO 27001) on authorized systems |

---

## 2. Prohibited Use

The following activities are **strictly prohibited** when using Siyarix or any of its components:

### 2.1 Unauthorized Access

- Scanning, probing, or attacking systems without explicit written authorization from the system owner
- Attempting to bypass access controls, authentication mechanisms, or security boundaries of systems you do not own
- Credential stuffing, password spraying, or brute-force attacks against unauthorized targets
- Using Siyarix to discover or exploit vulnerabilities without authorization

### 2.2 Malicious Activities

- Deploying ransomware, malware, worms, trojans, viruses, or any form of malicious code
- Participating in botnet operations, command-and-control (C2) infrastructure, or DDoS attacks
- Engaging in cryptojacking, resource hijacking, or unauthorized use of computing resources
- Developing, distributing, or hosting exploit kits intended for illegal use
- Creating or distributing backdoors, rootkits, or persistence mechanisms

### 2.3 Social Engineering & Deception

- Conducting phishing, vishing, smishing, or pretexting campaigns without explicit authorization
- Creating or distributing deceptive communications intended to harm, defraud, or manipulate individuals or organizations
- Impersonation of individuals, organizations, services, or brands for malicious purposes
- Operating fraudulent websites, services, or communications channels

### 2.4 Critical Infrastructure Disruption

- Operations intended to disrupt, degrade, or destroy critical infrastructure
- Attacks on healthcare systems, emergency services, public utilities, or government systems without explicit lawful authorization
- Targeting industrial control systems (ICS/SCADA), operational technology (OT), or cyber-physical systems without authorization
- Operations that could reasonably result in physical harm, property damage, or loss of life

### 2.5 Illegal Surveillance

- Monitoring individuals without their knowledge, consent, or a lawful legal basis
- Unauthorized interception of communications or network traffic
- Collection, processing, or exfiltration of personal data without lawful authority or valid consent
- Operation of unauthorized monitoring or surveillance infrastructure

### 2.6 Privacy Violations

- Doxxing, publishing, or distributing private information without consent
- Exfiltration of personally identifiable information (PII), protected health information (PHI), or cardholder data (CD) without authorization
- Violation of data protection regulations including but not limited to GDPR, CCPA, PIPEDA, LGPD, or POPIA
- Use of the platform to create or augment surveillance systems targeting protected groups or individuals

### 2.7 Nation-State Abuse

- Use in offensive cyber operations conducted by or on behalf of any nation-state, government, or state-sponsored entity without lawful international mandate authorization
- Development of cyber weapons, offensive capabilities, or attack tools targeting civilian infrastructure
- Use in military cyber operations without appropriate legal oversight and rules of engagement

### 2.8 Weaponization

- Modifying Siyarix for the purpose of causing physical harm, property damage, or loss of life
- Integration with weapons systems, weapons platforms, or military-grade offensive cyber capabilities
- Use of the platform to facilitate or enable extrajudicial activities

### 2.9 Illegal Content

- Using Siyarix to generate, distribute, or interact with illegal content
- Using the platform to circumvent content restrictions in jurisdictions where such circumvention is illegal
- Using AI provider integrations to generate prohibited content under the provider's terms of service

---

## 3. Authorized Use Requirements

When using Siyarix for permitted security testing, you must adhere to the following requirements:

1. **Written Authorization**: Always obtain explicit written permission from the system owner before testing any system you do not own. Retain this authorization for the duration of your engagement.

2. **Scope Boundaries**: Do not exceed the authorized scope of testing engagements. Any discovered assets outside scope must be reported without further investigation.

3. **Data Handling**: Securely handle, minimize collection of, and promptly destroy any data collected during testing. Apply the principle of data minimization.

4. **Responsible Reporting**: Report security findings to system owners in a timely, clear, and responsible manner. Provide actionable remediation guidance.

5. **Least Privilege**: Use the minimum access level, tooling, and techniques necessary to accomplish the authorized objective.

6. **Risk Assessment**: Assess the potential impact of testing activities before execution. Implement safeguards to prevent service disruption.

7. **Documentation**: Maintain clear records of authorization, scope, methodology, findings, and data handling procedures for each engagement.

---

## 4. Responsible Disclosure

If you discover a security vulnerability in Siyarix itself:

- **Do not** open a public GitHub issue or disclose the vulnerability publicly
- Follow the coordinated disclosure process in [SECURITY.md](SECURITY.md)
- Allow a reasonable embargo period (typically 90 days) for patches before public discussion
- Report using GitHub Security Advisories or private contact channels

---

## 5. Compliance & Enforcement

Violation of this policy may result in:

- Revocation of contributor privileges and repository access
- Removal from community platforms and communication channels
- Reporting to relevant law enforcement or regulatory authorities if illegal activity is involved
- Legal action in cases of willful harm, criminal conduct, or gross negligence
- Public disclosure of policy violations, where appropriate and lawful

---

## 6. Questions & Reporting

If you are unsure whether a particular use case is permitted, or to report a suspected violation of this policy:

- Submit a **private** GitHub Security Advisory at `https://github.com/mufthakherul/siyarix/security/advisories`
- Contact the maintainers via private channels listed in [SECURITY.md](SECURITY.md)

---

*This policy supplements the GNU Affero General Public License v3.0 or later under which Siyarix is distributed. It does not create binding legal obligations beyond those already imposed by applicable law. Violations may result in exclusion from project communities and contributor programs.*

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
