# Siyarix Project Governance

**Effective Date:** June 2026  
**Version:** 1.0.0  
**Applies to:** Siyarix v1.0.0 and all future versions

---

## 1. Overview

Siyarix is an open-source community project released under the GNU Affero General Public License v3.0 or later. This governance model defines how decisions are made, how maintainers are selected and empowered, how the project evolves, and how community members participate in shaping the project's direction.

This governance model is designed to be transparent, meritocratic, and sustainable. It draws inspiration from established open-source governance models including the [GitHub Minimum Viable Governance](https://github.com/github/MVG) framework.

---

## 2. Project Roles

### 2.1 Maintainers

Maintainers are the stewards of the Siyarix project. They are responsible for:

- Reviewing and merging pull requests
- Triaging, prioritizing, and responding to issues
- Setting the project roadmap and technical direction
- Managing release planning, versioning, and publication
- Enforcing community standards and the Code of Conduct
- Maintaining project security and responding to vulnerabilities
- Managing project assets including package registries, domain names, and social media
- Onboarding new contributors and fostering community growth

**Current Maintainer:** MD MUFTHAKHERUL ISLAM MIRAZ ([@mufthakherul](https://github.com/mufthakherul))

**Adding Maintainers:** New maintainers may be added by existing maintainer consensus from among contributors who have demonstrated sustained, high-quality contributions, sound judgment, and alignment with the project's values and vision.

**Removing Maintainers:** Maintainers who are inactive for a sustained period (6+ months) or who violate the Code of Conduct may have their status revoked by maintainer consensus.

### 2.2 Contributors

Contributors are individuals who submit pull requests, file detailed issues, participate in design discussions, or otherwise actively contribute to the project. All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and [Contributing Guide](CONTRIBUTING.md).

### 2.3 Community Members

Community members participate in discussions, report bugs, suggest features, provide support to other users, and help build the project ecosystem. All community members are valued participants and are encouraged to become contributors.

---

## 3. Decision-Making

### 3.1 Maintainer Authority

Maintainers have final authority over:

- Acceptance or rejection of contributions
- Project roadmap, priorities, and strategic direction
- Release timing, version numbering, and content
- Moderation decisions and Code of Conduct enforcement
- Project infrastructure, tooling, and automation decisions

### 3.2 Consensus & Voting

- **Routine decisions** (individual PRs, bug fixes, minor features) are made by maintainer review and approval
- **Significant decisions** (license changes, major architecture changes, new maintainer appointments) require maintainer consensus and community discussion
- **Disputes** that cannot be resolved through discussion are escalated to the maintainer team for final resolution
- **Voting**: When formal votes are necessary, each maintainer has one vote. Simple majority decides routine matters; supermajority (2/3) is required for significant decisions

### 3.3 Community Input

Community input is gathered through:

- [GitHub Issues](https://github.com/mufthakherul/siyarix/issues) for bug reports and feature requests
- [GitHub Discussions](https://github.com/mufthakherul/siyarix/discussions) for design proposals and community conversations
- Pull request reviews where community members can comment on proposed changes
- Periodic community surveys or roadmap feedback requests
- Security advisories for vulnerability coordination

---

## 4. Contribution Process

The detailed contribution workflow is documented in [CONTRIBUTING.md](CONTRIBUTING.md). Key principles:

- All contributions are subject to review
- All contributors must adhere to the Code of Conduct
- All contributions are licensed under AGPL-3.0-or-later (inbound = outbound)
- Significant design changes should be discussed before implementation

---

## 5. Release Management

### 5.1 Versioning

Siyarix follows [Semantic Versioning 2.0.0](https://semver.org/):

| Component | Meaning |
|-----------|---------|
| **Major (1.x.x)** | Breaking changes to public API, CLI, or data formats |
| **Minor (x.1.x)** | New features, non-breaking additions, deprecation notices |
| **Patch (x.x.2)** | Bug fixes, security patches, performance improvements |
| **Pre-release (x.x.x-alpha/beta/rc.N)** | Development, testing, and release candidate builds |

### 5.2 Release Process

1. Changes accumulate on the `main` development branch
2. When a release is ready, a maintainer creates a release candidate branch from `main`
3. Release candidates undergo full test suite validation, integration testing, and security review
4. A signed GPG tag is created and pushed to the repository
5. Release artifacts are published to:
   - [PyPI](https://pypi.org/project/siyarix/) (pip)
   - [GitHub Releases](https://github.com/mufthakherul/siyarix/releases) (source, binaries)
   - Docker Hub / GitHub Container Registry (container images)
   - Package managers (Homebrew, Chocolatey, Winget, .deb) as applicable
6. Release notes are generated from commit history following the [Keep a Changelog](https://keepachangelog.com/) format

### 5.3 Security Releases

Security patches are expedited through the release process. Depending on severity, a security-only patch release may be published outside the regular release cadence. See [SECURITY.md](SECURITY.md) for the vulnerability handling process.

### 5.4 Long-Term Support (LTS)

- The latest major version receives active development and security patches
- The previous major version receives critical security patches for 6 months after a new major release
- LTS policy is reviewed annually

---

## 6. Security Governance

- Security vulnerabilities are handled through the process defined in [SECURITY.md](SECURITY.md)
- Maintainers have access to the GitHub Security Advisory workflow for private vulnerability coordination
- Security patches are prioritized for the latest stable release and backported to the LTS release
- Security-related changes are tagged with the `security` type in commit messages
- Automated security scanning (CodeQL, Dependabot, secrets scanning) runs on every commit and pull request

---

## 7. Licensing Governance

- Siyarix is licensed under **GNU Affero General Public License v3.0 or later** (SPDX: `AGPL-3.0-or-later`)
- License changes require community discussion, maintainer consensus, and a supermajority vote
- All contributions are made under the same license (inbound = outbound policy)
- Third-party dependencies must have licenses compatible with AGPL-3.0-or-later

---

## 8. Code of Conduct Enforcement

The maintainer team is responsible for enforcing the [Code of Conduct](CODE_OF_CONDUCT.md). Reports are handled confidentially and with respect for all parties involved. Enforcement actions follow the graduated response defined in the Code of Conduct.

---

## 9. Amendments

This governance document may be amended by maintainer consensus. Significant changes will be communicated to the community via GitHub Discussions and release notes. A 30-day comment period is provided for substantive amendments before they take effect.

---


*SPDX-License-Identifier: AGPL-3.0-or-later*

