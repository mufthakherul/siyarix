## [unreleased]

### Bug Fixes

- Resolve ruff duplicate keys, formatting, and detect-secrets pragmas (fixes #112)
- *(lint)* Configure ruff ignores, sort stubs __all__, and clean up playbook test imports
- *(lint)* Fix import ordering in stubs.py and remove unused noqa in threat_intel.py

### Features

- Wire scan notify dispatcher, harden termux installer, and add starter playbooks
- *(threat-intel)* Implement offline MITREAttackDB and ThreatIntelFeed with technique mapping and CVE catalog

### Miscellaneous Tasks

- Sync all version references to 1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1

### Styling

- Auto-format code with ruff

### Build

- *(deps)* Bump pyasn1 in the uv group across 1 directory (#114)

### Ci

- Fix setup-nuget, git-cliff install, winget publish error, labeler v5 syntax, and lychee argument error
- Run publish-chocolatey on windows-latest for native NuGet support
- Set default bash shell for publish-chocolatey job on Windows
- Update nuspec schema version to 2010/07 for compatibility with NuGet 7.x
- Use choco CLI for Chocolatey package packaging and publishing on Windows


