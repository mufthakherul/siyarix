# Siyarix Project Governance

**Effective Date:** May 2026
**Version:** 1.0.0

---

## 1. Overview

Siyarix is an open-source community project. This governance model describes how decisions are made, how maintainers are selected, and how the project evolves.

---

## 2. Project Roles

### 2.1 Maintainers

Maintainers are responsible for:

- Reviewing and merging pull requests
- Triaging issues
- Setting project direction and roadmap
- Managing releases
- Enforcing community standards
- Maintaining project security

**Current maintainer:** MD MUFTHAKHERUL ISLAM MIRAZ (@mufthakherul)

### 2.2 Contributors

Contributors are anyone who submits pull requests, files issues, or participates in discussions. All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

### 2.3 Community Members

Community members participate in discussions, report bugs, suggest features, and help other users. All community members are valued participants in the project ecosystem.

---

## 3. Decision-Making

### 3.1 Maintainer Authority

Maintainers have final authority over:

- What contributions are accepted
- Project roadmap and priorities
- Release timing and content
- Moderation decisions

### 3.2 Consensus & Voting

- Routine decisions are made by maintainer consensus
- Significant decisions (license changes, major architecture changes) should involve community discussion
- Disputes are resolved by the maintainer team

### 3.3 Community Input

Community input is gathered through:

- GitHub Issues and Discussions
- Pull request reviews
- Periodic surveys or roadmap discussions

---

## 4. Contribution Process

See [CONTRIBUTING.md](CONTRIBUTING.md) for the detailed contribution workflow.

---

## 5. Release Management

### 5.1 Versioning

Siyarix follows [Semantic Versioning 2.0.0](https://semver.org/):

- **Major (0.x.x)**: Pre-release development — breaking changes may occur
- **Minor (x.1.x)**: New features, non-breaking additions
- **Patch (x.x.2)**: Bug fixes, security patches

### 5.2 Release Process

1. Changes accumulate on the `main` branch.
2. When a release is ready, a maintainer creates a release candidate branch.
3. Release candidates are tested against the full test suite.
4. A signed tag is created and pushed.
5. Release artifacts are published to PyPI and GitHub Releases.
6. Release notes are generated from commit history.

### 5.3 LTS Releases

(Not applicable at current pre-release stage. LTS policy will be defined at v1.0.0.)

---

## 6. Security Governance

- Security vulnerabilities are handled through the process in [SECURITY.md](SECURITY.md).
- Maintainers have access to the security advisory workflow on GitHub.
- Security patches are prioritized for the latest release.

---

## 7. Licensing Governance

- Siyarix is licensed under AGPL-3.0.
- License changes require community discussion and maintainer consensus.
- All contributions are made under the same license (inbound = outbound).
- Commercial licensing options are available separately (see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)).

---

## 8. Code of Conduct Enforcement

The maintainer team is responsible for enforcing the [Code of Conduct](CODE_OF_CONDUCT.md). Reports are handled confidentially and with respect for all parties involved.

---

## 9. Amendments

This governance document may be amended by maintainer consensus. Significant changes will be communicated to the community.

---

## 10. Acknowledgments

This governance model draws inspiration from established open-source projects and community best practices, including the [GitHub Minimum Viable Governance](https://github.com/github/MVG) model.

---

*SPDX-License-Identifier: AGPL-3.0-only*
