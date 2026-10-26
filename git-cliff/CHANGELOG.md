## [unreleased]

### Bug Fixes

- Resolve ruff duplicate keys, formatting, and detect-secrets pragmas (fixes #112)
- *(lint)* Configure ruff ignores, sort stubs __all__, and clean up playbook test imports
- *(lint)* Fix import ordering in stubs.py and remove unused noqa in threat_intel.py
- *(security)* Resolve all Dependabot vulnerabilities in uv.lock and upgrade cryptography and pip
- *(quality)* Remove unused variables and logger to resolve CodeQL alerts 1717, 1718, 1719
- *(ci)* Resolve 5 failing workflows (isort lint, playbook test wrap, trivy scan, pytest-timeout, stale branches)
- *(deps)* Relax cryptography lower bound to >=42 for Kali/Debian compatibility
- *(plugins)* Restore robust plugin loader, fix planner test assertion, and annotate static checks
- *(repl)* Disable mouse interception to enable terminal text selection, add /copy command and F5 shortcut
- Close SX-012/024/031 and harden production readiness
- *(chat)* Surface CLS skill-compile background task failures
- *(vault)* Log obsolete credentials rename failures
- *(async)* Log background subagent and worker-pool task failures
- Close high-severity hunt findings (queue, audit, SSRF, playbooks)
- Enforce deep-scan scope and refuse silent vault key rotation
- Production defaults for gate, secrets, and offline retry queue
- Close remaining hunt findings (rm flags, plugins, review, toml)
- *(plugins)* SSRF-safe https registry/fetch and git clone
- Block local-provider HTTP redirects; gate production-check
- Harden ollama/health/chat HTTP probes against redirects
- *(offline-queue)* Bound replay cycles; document hardening
- Harden playbooks and stealth decoys
- Gate kwargs-only tools; reclaim by claimed_at
- *(onboarding)* SSRF-safe local provider health probes
- Close workflow soft-fail, TI SSRF, IPv4-mapped local URL bypass
- *(types)* Satisfy mypy for IPv4-mapped unwrap
- *(types)* Clear mypy getattr summary typing in scan core
- *(onboarding)* Resolve archive members under extract root
- Enforce SIYARIX_ALLOWED_SCOPE on kwargs-only tool steps
- *(workflow)* Skip nodes blocked by unmet edge conditions
- Include args/flags in scope synopsis for kwargs tools
- *(onboarding)* Skip symlink members during archive extract
- *(onboarding)* Skip symlink/hardlink archive members
- *(workflow)* Apply playbook env allowlist to edge conditions
- Always fold kwargs into allowed-scope synopsis
- Re-validate webhook URLs immediately before connect
- *(offline-queue)* Store created_at with SQLite datetime('now')
- *(security)* Https-only webhooks, DLP sync, safer .env and review UX
- *(security)* Redact URL passwords in SecretRedactor
- *(onboarding)* Sanitize llama.cpp release tags and redirect hosts
- *(http)* Refuse redirects on Gemini and provider API probes
- *(ux)* Fail-closed tty_confirm and clearer non-TTY refusals
- *(plugins)* Reject cleartext http:// git remotes early
- *(security)* Close hunt P0/P1 hang, SSRF, dd, cache, and env gaps
- *(security)* Pin webhook IPs, enforce queue deps, sandbox loader
- *(plugins)* Sandbox legacy loader paths without double-loading
- *(security)* Share destructive checks and pin TI/decoy HTTPS
- *(security)* Precise system-rm matching; align destructive tests
- *(security)* Re-assert destructive hard-blocks after registry review EDIT
- *(security)* Unwrap IPv4-mapped addresses in webhook SSRF checks
- *(security)* Refuse HTTP 3xx on IP-pinned HTTPS requests
- *(security)* Close find-delete, disk-wipe, scope-obfuscation, and review-default gaps
- *(security)* Block more disk/interpreter wipes; expand short IPv4 scope
- *(security)* Close ATA wipe, partition-tool, quote, and IP-obfuscation gaps
- *(security)* Fix hex-dotted IPv4; block btrfs/lvm wipe paths; add doctor alias
- *(security)* Block chmod root-equiv, inet_aton IPs, rsync/ntfs/interpreter wipes
- *(security)* Block pathlib/IO/writeFile, qemu-img, rsync --delete, mv system
- *(security)* Scrub hex-dotted IPs before short-form extract
- *(security)* Block chmod -Rf, curl -o disk, auth ln/cp wipes
- *(security)* Block chmod -R after mode; auth redirects; wget long -O
- *(security)* Redact URL passwords that contain embedded @
- *(security)* Block curl -o/dev, dd of=auth, interpreter auth writes
- *(security)* Block urlretrieve/gpg/openssl disk writes and root extracts
- *(security)* Close wipe-tool, path-.., dotenv, and download bypasses
- *(security)* Block os.system/exec wipes; doctor readiness score
- *(security)* Redact Groq gsk_ and SIYARIX_*_KEY assignments
- *(security)* Block diskutil/asr, Win cmdlets, dir+/dev downloads
- *(security)* Block list-argv subprocess wipes; parallel scan rollup
- *(security)* Harden mmcblk/md/7z extract, PEM body, file:// scope
- *(security)* Block glued tar/unzip root extract and lftp/cmake/Clear-Partition
- *(security)* Block --directory=/ extract and scp/PhysicalDisk wipes
- *(security)* Normalize extract dests; zstd/split; scope schemes; PEM/dotenv
- *(security)* Rm option-order, auth/disk writers, zipfile, scope 0/IDN
- *(scope)* Do not treat IPv6 hextets as integer IPv4 hosts
- *(security)* Protect persistence paths; basename scope tools; TLS dotenv
- *(security)* Tee -a auth, dpkg/unsquashfs/git root, mount bind, procfs
- *(security)* Gdd/gtar/mke2fs, unar -o, cp -t auth, pkg --root, smbclient UNC
- *(security)* Apk -p/bootstrap root, mount -B, shuf -o, UNC/scp/socat scope
- *(security)* Glued -t, mount bind commas, tar -P, shutil).copy, ssh -o
- *(security)* Dotenv keys/inject, proxy/jump scope, executor fold, pip root
- *(security)* Zipfile dest, symlink, brace/ANSI rm, bash -c, socat SOCKS
- *(security)* Glued -o/-x/-J, tar -xPf, gawk -iinplace, install setuid
- *(security)* Mid-path braces, opkg -o, su/script -c, RSYNC dotenv
- *(security)* IFS rm, glued -m4755, -J comma hops, auth writers, java dotenv
- *(security)* Brace suffix, ANSI octal, sg_dd, preproxy, forwards, openssl/git
- *(security)* Gpg/openssl full auth, misc writers, DB/docker scope, dotenv
- *(docs)* Align operator-safety with researcher mission
- *(security)* Partclone/ntfsclone, auth rm, sshuttle/chisel scope, ansible dotenv
- *(security)* Close hunt27 gzip/e2image, glued hosts, brute scope, ansible dotenv
- *(security)* Close hunt28 compress/inplace/ginstall/age, glued scope, dotenv

### Documentation

- Record verified pytest/mypy production gate results
- Note DNS private-IP rejection for SX-012
- *(user)* Document production-check, compliance probes, offline reports
- *(user)* Finish production-check and compliance probe notes
- *(readme)* Link production-check and PRODUCTION_READINESS
- Finalize production readiness residual hardening notes
- Refresh production readiness gate counts
- *(user)* Document playbook env secret redaction policy
- Note workflow/TI/IPv4-mapped hardening in readiness notes
- *(changelog)* Record TI/workflow/IPv4-mapped security fixes
- Note kwargs-only scope enforcement; refresh gate counts
- Refresh readiness notes for edge conditions (6019 tests)
- Refresh production readiness counts (6022 tests)
- *(changelog)* Record scope fold, compliance probes, webhook revalidation
- *(wiki)* Sync parallel scan and playbook env secret guidance
- Refresh production gate counts (6059 pytest)
- *(changelog)* Note Gemini/provider redirect refusals
- Refresh production gate counts after tty_confirm harden
- Refresh production gate counts (plugin http reject)
- Refresh production gate counts after hunt batch
- Refresh production gate counts after IP-pin batch
- Note registry EDIT hard-block and refreshed gate counts
- Document production security env vars and production-check fields
- Refresh gate counts after IPv4-mapped webhook unwrap
- Refresh counts after pinned-HTTPS 3xx refusal
- Refresh gate counts after find-delete/scope hunt batch (6119)
- Refresh gate counts after wipe/short-IPv4 batch (6129)
- Refresh gate counts after ATA/IP-obfuscation hunt batch (6146)
- Refresh gate counts after hex-dotted/doctor batch (6152)
- Refresh gate counts after chmod/inet_aton/rsync hunt batch
- Refresh gate counts after pathlib/qemu-img/rsync-delete batch (6155)
- Refresh gate counts after chmod-Rf/curl-o/auth wipe batch (6162)
- Note doctor live hard-block probes in readiness (6162)
- Refresh gate counts after chmod-order/auth-redirect batch (6171)
- Refresh gate counts after URL-password @ redaction (6172)
- Refresh gate counts after curl-o/dev and auth-write batch (6179)
- Refresh gate counts after urlretrieve/gpg/tar-extract batch (6184)
- Refresh gate counts after hunt6 wipe/path/dotenv batch (6209)
- Refresh gate counts after os.system/doctor-score batch (6214)
- Refresh gate counts after Groq/KEY redaction batch (6215)
- Refresh gate counts after diskutil/Win-cmdlet hunt8 batch (6233)
- Refresh gate counts after list-argv/parallel-rollup batch (6237)
- Refresh 6250 gate counts; probe mmcblk/7z/file://
- Refresh gate counts after extract/lftp/cmake hard-block batch (6255)
- Refresh gate counts after directory=/scp/PhysicalDisk batch (6260)
- Refresh gate counts after hunt11 extract/scope/PEM/dotenv batch (6276)
- Refresh gate counts after hunt12 auth/disk/scope batch (6307)
- Refresh gate counts after hunt13 persistence/scope/TLS batch (6325)
- Refresh gate counts after hunt14 tee/dpkg/procfs/scope batch (6342)
- Refresh gate counts after apk/bootstrap/UNC scope batch (6370)
- *(changelog)* Note campaign persistence and hunt27 security closures

### Features

- Wire scan notify dispatcher, harden termux installer, and add starter playbooks
- *(threat-intel)* Implement offline MITREAttackDB and ThreatIntelFeed with technique mapping and CVE catalog
- *(ui)* Elevate CLI-UI quality with rich tables, playbook show, compliance frameworks, cache stats, and Windows path hardening
- *(ux)* Improve terminal window, input methods, output systems, and scrolling
- *(onboarding)* Add termux pkg, parrot/blackarch/athena detection, express mode, and python 3.11 support
- *(tools)* Add comprehensive tool installation, uninstallation, modification, and CLI/REPL suite
- *(config)* Add dynamic config engine, profiles, validation, masking, and CLI/REPL suite
- *(ai)* Enterprise AI engine overhaul with semantic pruning, tool repair, anti-looping guard, grounding verifier, and caching
- *(plugins)* Enterprise plugin architecture, CLI/REPL management, registry client, and autonomous agent integration
- *(installer)* Enterprise-grade installers, uninstallers, and deployment documentation
- *(compliance)* Add honest local probes for SX-025 controls
- Parallel multi-target scans and gated registry factory
- Tag parallel-scan findings with source target
- *(cli)* Show parallel scan summary panel
- *(workflow)* Honor playbook conditions and retries
- *(workflow)* Evaluate edge conditions fail-closed
- *(compliance)* Add PermissionGate and webhook SSRF local probes
- *(cli)* Surface SIYARIX_ALLOWED_SCOPE in production-check
- *(cli)* Surface command_review and destructive_guard in production-check
- *(cli)* Doctor probes live hard-blocks and inet_aton scope
- *(scan)* Per-host multi-target workers + researcher doctor UX
- *(campaign)* Persist multi-target campaigns; scan-quick/full --parallel

### Miscellaneous Tasks

- Sync all version references to 1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1
- *(release)* Update changelog for v1.0.1
- Lock mypy stub packages in uv.lock
- Drop unused datetime imports from offline_queue
- Add siyarix-residual-hunter project subagent

### Refactoring

- *(core)* Project-wide quality audit, eliminate mock artifacts, and fix non-interactive test execution

### Styling

- Auto-format code with ruff

### Testing

- Use resolvable host for notification webhook dispatch
- Avoid un-awaited AsyncMock in emit_sync fallback
- Expect PermissionGate synopsis for kwargs-only execute
- Register nikto for args/flags scope bypass cases
- Expect critical for cipher /w disk wipe

### Build

- *(deps)* Bump pyasn1 in the uv group across 1 directory (#114)
- Add make production-check target
- *(deps)* Bump actions/deploy-pages from 5.0.0 to 5.0.1

### Ci

- Fix setup-nuget, git-cliff install, winget publish error, labeler v5 syntax, and lychee argument error
- Run publish-chocolatey on windows-latest for native NuGet support
- Set default bash shell for publish-chocolatey job on Windows
- Update nuspec schema version to 2010/07 for compatibility with NuGet 7.x
- Use choco CLI for Chocolatey package packaging and publishing on Windows

### Security

- *(webhooks)* Reject destinations that resolve to private IPs


