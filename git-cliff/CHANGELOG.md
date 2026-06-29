## [unreleased]

### Bug Fixes

- *(release)* Update gh-pages action SHA, replace git-cliff-action with direct install, allow TestPyPI failure
- *(ci)* Fix workflow failures and configuration KeyError
- *(termux)* Add precompiled dependencies to installer
- *(ci)* Update downstream compatibility validations and lock threads version
- *(install)* Prevent powershell terminal from closing on exit and fix pipeline corruption
- *(session)* Resolve encoding issues and integrate audit logger
- *(typing)* Resolve mypy type errors in Prompt.ask and session export
- *(ci)* Add security-events permissions for docker publish and follow redirects in homebrew archive check
- *(core)* Remove redundant comparison, fix regex typo, and clean up unused parser regexes
- *(core)* Refactor sudo password cache, declare ToolHandler public, and clean up unused imports/variables
- *(lint)* Remove unused import in zgrab_parser and unused type ignore in executor_autonomous
- *(lint)* Resolve mypy type check and ruff import order warnings
- *(lint)* Resolve remaining unused variables, empty excepts, and ineffectual awaits
- *(lint)* Resolve unused global/local variables and type checking issues in CLI/parsers/tests
- *(security)* Resolve final batch of CodeQL scanning alerts and add custom codeql-config.yml to ignore noisy quality checks
- *(typecheck)* Resolve dict item types in scripts/test_platform.py to satisfy pre-commit mypy
- *(security)* Resolve final Python CodeQL alert, suppress urlopen warnings, and disable Scorecard SARIF uploads
- *(ci)* Update labeler.yml format, fix auto-merge enableAutoMerge function, and prevent version-validation bash dollar expansion
- *(ci)* Align all CodeQL actions to v3 commit hash to prevent version mismatch failure

### Documentation

- Convert github-style alert callouts to native mkdocs-material admonitions
- Fix home and map page front matter and header welcome note positioning
- Update changelog (#70)
- Update changelog (#89)
- Update changelog (#90)
- Update changelog (#91)
- Update changelog (#92)

### Features

- *(provider_utils)* Make health check timeout configurable
- *(repl)* Perform live health checks for local providers in status gathering
- *(ui)* Render each provider's real-time status on its own line in the LLM Status panel

### Security

- *(deps)* Bump trufflesecurity/trufflehog (#81)

### Styling

- *(docs)* Revamp stylesheet to improve sidebar, scrollbars, tables, and light mode contrast
- Fix linting issues from previous commit
- Fix ruff formatting from previous typing commit
- Format modified files with ruff
- Apply pre-commit line endings, json formatting, and ruff assertion fixes
- Apply pre-commit formatting to git-cliff/CHANGELOG.md

### Testing

- Fix duplicate dictionary keys and identical expression comparison warnings

### Build

- Update dependency lock files (#88)
- *(deps)* Bump actions/upload-artifact from 4.6.2 to 7.0.1 (#87)
- *(deps)* Bump softprops/action-gh-release from 2.6.2 to 3.0.1 (#86)
- *(deps)* Bump actions/upload-pages-artifact from 3.0.1 to 5.0.0 (#85)
- *(deps)* Bump actions/deploy-pages from 4.0.5 to 5.0.0 (#84)
- *(deps)* Bump github/codeql-action/upload-sarif (#83)
- *(deps)* Bump amannn/action-semantic-pull-request from 5 to 6 (#82)
- *(deps)* Bump github/codeql-action/autobuild from 3.36.2 to 4.36.2 (#80)
- *(deps)* Bump docker/metadata-action from 5.10.0 to 6.1.0 (#79)
- *(deps)* Bump docker/setup-buildx-action from 3.12.0 to 4.1.0 (#78)

### Ci

- Pin lock-threads action to secure commit hash
- Add workflow_dispatch to CodeQL Weekly Deep Scan


