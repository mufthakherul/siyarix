# Production readiness — SX remediation status

Siyarix is an AI orchestration assistant for **security researchers, pentesters,
SOC analysts, and other cybersecurity professionals** — to run authorized work
faster, deeper, and more reliably. Hardening here is **operator safety**
(prevent accidental disk wipe, auth-file clobber, or out-of-engagement pivots),
not a restriction on legitimate security tooling. `SIYARIX_ALLOWED_SCOPE` is
optional; when unset, scope checks are a no-op.

This note tracks the audit items from the September 2026 baseline (`177acb6`)
against the current tree on `fix/production-hardening-sx-remediation`.

## Verified closed (evidence in tests / code)

| ID | Topic | Evidence |
| --- | --- | --- |
| SX-001 | Fail-closed shell review | `shell_review.py`, `tests/test_shell_review.py` |
| SX-002 | Execute edited commands | `registry.py` revalidate + kwargs update |
| SX-003 | Autonomous permission gate | `executor_autonomous._exec_one` → `_check_permissions` |
| SX-004 | Target scope IPv6/CIDR | `target_scope.py`, `tests/test_target_scope.py` |
| SX-005 / SX-023 | Report XSS + badge contrast | Jinja2 autoescape + CSP, `tests/test_report_xss.py` |
| SX-006 | Offline queue commits | `offline_queue._transaction`, `tests/test_sx006_*` |
| SX-007 / SX-008 | Credential envelopes / password vault | `credential_store.py`, `tests/test_sx007_*` |
| SX-009 | Audit hash after redact | `audit_log.py`, `tests/test_sx009_*` |
| SX-010 | Dependency-aware scheduling | `executor_autonomous._execute_dependency_aware` |
| SX-011 | CVSS 3.1 Roundup | scores `6.5` for the FIRST example; `tests/test_sx011_*` |
| SX-013–SX-019 | CLI contracts / playbooks | `tests/test_sx_cli_contracts.py` |
| SX-021 | Rich Tree API | `chat/console.py` uses `.add` |
| SX-027 | Redis defaults | compose `profiles: [redis]`, auth, loopback bind |
| SX-028 | Docker target / entrypoint | Makefile `python` target; settings.toml detection |
| SX-029 | CI security gates | `scripts/ci_security_gate.py` |
| SX-030 | Hanging subagent test | `tests/test_core.py` |
| SX-032 | AnyIO advisories | `uv.lock` → 4.15.1 (`poetry.lock` removed; see `LOCKFILES.md`) |
| SX-012 | Webhook SSRF destination policy | Literal IP + DNS→private reject; notification path; `tests/test_sx012_webhook_ssrf.py` |
| SX-020 | Hatchling / Twine metadata | `hatchling>=1.21.1,<1.27`; `twine check` passes |
| SX-026 | Rust parser adapters | `siyarix_rust_parsers` function exports via Python adapters |
| SX-031 | mypy consolidation | `.mypy.ini` ↔ `[tool.mypy]`; `mypy src/siyarix` clean; CI runs project mypy |

## Remaining / follow-up

| ID | Status | Notes |
| --- | --- | --- |
| SX-024 | Closed | Offline REPL skips connectivity monitor; HTML reports default `offline=True` (system fonts); online mode widens CSP for Google Fonts only |
| SX-025 | Partial→probes | Local probes for audit chain / shell-review / credential store / PermissionGate / webhook SSRF policy; remaining controls stay `NOT_EVALUATED` with disclaimer |
| RH-01–05 | Closed | Lexical path normalize before auth/block regexes; `cp --parents` / `rsync -R` auth reconstruction blocked |
| RH-04 | Closed | Shared `dotenv_guard` blocks PERLLIB / Java aliases / CORECLR_* / BASH_FUNC / editors / Ansible plugins / GOCACHEPROG / … |
| RH-06 | Closed | Scope blocks proxychains/torsocks/tunnels, `psql service=`, `ssh -D` |
| SX-A03 | Closed | `_prepare_env` scrubs sudo/master/API secrets from child processes |
| SX-A04 | Closed | Full SHA-256 audit digests; `verify_chain` reads full on-disk JSONL (legacy 16-char accepted) |
| SX-A05 | Closed | Agent PermissionGate uses `permission_gate_enabled()` env-only (no settings.toml silent off) |
| SX-A07/A08 | Closed | `*.enc` chmod 600; config dir 0700; KMS fail-closed when `SIYARIX_KMS_PROVIDER=aws` |
| FEAT/DOC | Partial | Compose API ports removed; classifiers Beta (no iOS); stub module warning; ghost TAXII/MISP/dashboard env scrubbed |
| SX-A02/A10/A11 | Closed | Plugin auto-pip off by default; PEP508-only requirements (reject paths/URLs/VCS); git/pip via `safe_run_sync` scrub; origin re-validated; no CWD index |
| SX-A06 | Closed | file_key warns by default; `--strict` / `SIYARIX_REQUIRE_MASTER_PASSWORD` / `SIYARIX_PRODUCTION` fail-closed; CredentialStore refuses file_key under those flags |
| CI | Partial | coverage 70%; Trivy CRITICAL exit 1; `production-check` job; stress/chaos markers; workflows use `uv pip` (not unlocked `pip install -e`) |
| SX-A01 | Partial+ | Lab: `SIYARIX_TRUST_PLUGINS=1`; production requires `=force`; host AST + scrubbed-subprocess compile preflight; production blocks high-risk entrypoint imports (`ctypes`/`pty`/…); optional `bwrap --unshare-net` preflight via `SIYARIX_PLUGIN_OS_ISOLATE` (default on in prod when bwrap present; `=force` fails closed if missing); `register_tools` still in-process |
| RH-29 | Closed | chisel `R:socks` / `:socks` scanned before hop-host break (in-scope hop cannot pivot) |
| RH-30 | Closed | sshuttle `0/0` / `0.0.0.0/0` / `::/0` full-tunnel blocked under scope |
| RH-31 | Closed | Child-env scrub: `AWS_ACCESS_KEY_ID`, bare `*_KEY`, `*_SECRET_KEY`, framework `SECRET_KEY` |
| RH-32 | Closed | `pproxy` / `proxy.py` scope-blocked tunnel wrappers |
| RH-33 | Closed | `CONSUL_*` / `VAULT_ADDR` / `CLICKHOUSE_HOST` / `cqlsh` / clickhouse client under scope |
| RH-34 | Closed | `docker context use` / `--connection` hide daemon — blocked under scope |
| RH-35 | Closed | `gem unpack --target /`, `aunpack -X /` extract-to-root blocked |
| RH-36 | Closed | Dotenv skips `BROWSER` / Guile / pip index / `GRPC_PROXY` / Vault / GDK / NSS wrapper / Electron pivots |
| RH-37 | Closed | `redsocks` / `microsocks` scope-blocked tunnel wrappers |
| RH-38 | Closed | `pip install --target=/` install-root pivot blocked |
| RH-39 | Closed | Dotenv skips `MITMPROXY_CONFDIR` / `REDSOCKS_CONF` / `*_CONFDIR` pivots |
| RH-40 | Closed | kubectl/oc/helm/kustomize: stop treating verbs as hosts; block `--context` / `use-context`; validate `--server` |
| RH-41 | Closed | Wave7 hunter: zpool/mdadm/pvcreate create-on-disk; gem `--install-dir`; patool `--outdir`; bind `/etc`; `/lib/systemd` units; cargo `--root /`; podman `system connection use`; chisel `server --socks5`; dotenv CONSUL/NOMAD/ETCD/registry/SSH_PROXY |
| RH-42 | Closed | Persistence `/etc/init.d`/`autostart`/`NM dispatcher`; pnpm/composer/bundle install roots; `kpartx -a` on disks; kubectl `proxy`/`port-forward`; skopeo/buildah `docker://`; minikube/kind/istioctl wrappers; dotenv CONTAINERD/PIP/COMPOSE/DOCKER_CONTEXT |
| ARCH-01 | Partial | Extracted `cli/production_check.py` + `cli/audit_cmds.py` + `cli/tools_cmds.py` + `cli/config_cmds.py` from CLI god-module |
| FEAT-02 | Honest | `siyarix[api]` reserved but **not** pulled by `[all]` (no in-tree HTTP server) |
| MOD-P0 | Closed | Dropped dead `google-generativeai` extras; Gemini REST via httpx; OPSEC isolate fail-closed without `memory_only`; stub/compaction honesty defaults |
| RH-43 | Closed | `mdadm -C`; PAM/`ld.so.conf.d`/spool cron; overlay/`bindfs` on `/etc`; `dpkg --root=/`; brook/mitmproxy SOCKS wrappers; dotenv `PGHOST`/MySQL/Redis transport |
| RH-45 | Closed | Mesh VPN (`zerotier`/`netbird`/`headscale`/`nebula`/`v2raya`/…) + `ip tuntap`/`tunnel` under scope |
| RH-46 | Closed | Wave9 hunter: conda/mamba `-p /`; nfs/cifs/sshfs/rclone/mergerfs onto `/|/etc`; profile.d/sysctl.d/udev/run-systemd persistence; cloud kubeconfig rewrite; lima/colima/lxd/singularity/privoxy/ipsec; emerge/xbps/yarn/bun/deno roots; dotenv DB/proxy/kube/crypto homes |
| RH-48 | Closed | Wave11 hunter: tmate/ttyd/gotty/wetty; tsh/tctl; mosh host-tool; pwncat; upterm; openvpn3; telebit; GNU parallel `:::` unwrap; dotenv TMATE/ARGOCD/TELEPORT/RCLONE/KUBE_API |
| RH-47 | Closed | Wave10 hunter: versioned wrapper basenames; autossh `-D`; sockd/tor/I2P/VPN activate/nmcli; k3d/k3s/microk8s/kubefwd; bare kubeconfig + AWS SSM/ECS; tmpfs/blockdev/encfs mounts; make/cmake/meson/stow roots; dotenv TORSOCKS/XDG_DATA/HELM_CONFIG/… |
| RH-44 | Closed | VPN/mesh/covert tunnels (`wg-quick`/`tailscale`/`clash`/`wstunnel`/`sshx`/…); `rclone mount`; `fuse-overlayfs`; `nix-env`/`guix -p /`; dotenv Tailscale/WireGuard/OpenVPN/Clash |
| FEAT-03 | Closed | Swarm gated behind `SIYARIX_EXPERIMENTAL_SWARM`; returns `not_implemented` |
| Dashboard | Closed | Local DB counts only; fabricated MFA/EDR/MTTD KPIs removed |
| CISA KEV | Closed | Feed status `planned` (was false `integrated`) |
| Dual lock | Closed | `poetry.lock` removed; `LOCKFILES.md` documents `uv.lock` SoT |
| Worker pool | Closed | Queue semaphore released on cancel-before-start via done-callback |
| OPSEC | Partial | `isolate()` honest: only `memory_only` in-process; Tor/DoH/MAC/netns `not_implemented` (success=False when requested) |
| Stubs | Closed | `AdversarialTester.test` / plugin scaffold / multi-wave aggregate success honesty; stub ensemble UI removed from chat |
| PermissionGate | Closed | Rate-limit state guarded with `threading.RLock` |
| Singletons | Closed | `PluginManager` / `ProviderManager` / `audit` singletons use locks (ProviderManager keeps bootstrap-safe lazy lock for tests) |
| RH-07 | Closed | `cp --parents` / `rsync -R` relative auth paths normalize `./etc` / `etc/./` before match |
| RH-08 | Closed | Glued `ssh -D9050` / `-oDynamicForward` / spaced `-o DynamicForward` blocked under scope |
| RH-09/10 | Closed | `nmap --proxies` + leading `ALL_PROXY=`/`HTTPS_PROXY=` env pivots blocked under scope |
| RH-11/12 | Closed | All `SIYARIX_*` + interpreter plugin-path pivots skipped from `.env` |
| RH-13 | Closed | `DATABASE_URL` / `REDIS_URL` / `CONNECTION_STRING` + userinfo `*_URL` scrubbed from child env |
| RH-14/15 | Closed | Leading `DOCKER_HOST=` / `CONTAINER_HOST=` / `GIT_SSH_COMMAND=` blocked under scope |
| RH-16 | Closed | `tsocks` treated as scope-blocked proxy wrapper |
| RH-17 | Closed | Glued `unzip -od /` extract-to-root blocked |
| RH-18 | Closed | Versioned GST plugin paths / `LIBRARY_PATH` / `KUBE_EDITOR` / cargo rustc wrapper skipped from `.env` |
| RH-19 | Closed | `ssh -w` TUN/TAP + `-o Tunnel=` blocked under scope |
| RH-20 | Closed | `gost` / `ss-local` / shadowsocks / v2ray / xray scope-blocked wrappers |
| RH-21 | Closed | `KUBECONFIG=` + `kubectl --kubeconfig` blocked under scope |
| RH-22 | Closed | `setfacl` / `chattr` / `setfattr` on auth paths blocked |
| RH-23 | Closed | `GTK_MODULES` / `GIO_EXTRA_MODULES` / Magick coder / `KUBECTL_EXTERNAL_DIFF` skipped from `.env` |
| RH-24 | Closed | Leading `MYSQL_HOST=` / `PGHOST=` / DSN transport env blocked under scope |
| RH-25 | Closed | `corkscrew` / `connect-proxy` scope-blocked wrappers |
| RH-26 | Closed | `nerdctl --host` / `kustomize --kubeconfig` blocked under scope |
| RH-27 | Closed | `ar --output /`, `mksquashfs`→block, `setcap cap_sys_admin` blocked |
| RH-28 | Closed | `HELM_KUBECONFIG` / `CC`/`CXX` / `TCLLIBPATH` skipped from `.env` |

## Premium ops

- `siyarix production-check` — security/config readiness table (`--strict` for CI); includes `permission_gate`, `tool_registry`, `command_review`, `destructive_guard`, and `plugin_trust`. Logic lives in `siyarix.cli.production_check`.
- `siyarix scan @targets.txt --parallel N` — true multi-target concurrent scans (merged findings).
- `make_tool_registry()` — shared PermissionGate-on-by-default construction for CLI/chat/plugins/core.
- `siyarix compliance run` — exit `2` on FAIL probes, `3` when NOT_EVALUATED remain (scaffold, not attestation).
- Local-provider `safe_http_*` helpers refuse redirects (block metadata pivots).

## Verification command

```bash
source .venv/bin/activate
mypy src/siyarix
python -m pytest tests/ -q -m "not e2e" --ignore=tests/test_stress_resilience.py
```

Latest local checks on this branch: **mypy clean (258 files)**; pytest **6456 passed**, 6 skipped, 62 deselected (`-m "not e2e"`, stress ignored). Mission-aligned operator-safety; unset engagement scope unrestricted; multi-target per-host scans.

Additional post-audit hardening (this branch): atomic offline-queue claim + stale reclaim,
audit flush under RLock, webhook https-only + no-redirect SSRF, playbook step registration, KG vuln
reporting, permission-gate empty-command ordering, injection validator fail-closed,
adversarial CRITICAL plan abort, deep-scan scope enforcement, vault key refuse-silent-rotate,
PermissionGate on by default, no sudo secrets in settings.toml, offline enqueue-on-failure only,
normalized `rm -fr/--recursive` destructive checks, plugin path/entrypoint sandboxing + pip
fail-closed, learned-skill review preserved, atomic settings.toml writes, cache_invalidate rowcount,
CLI multi-target `--parallel` concurrency, compliance status exit codes, chat/CLI registry factory,
DLP↔SecretRedactor pattern sync, broadened `.env` credential skips, non-TTY review guidance,
SecretRedactor URL-password redaction (no longer preserves the secret),
RegistryExecutor/workflow cyclic-dep SKIPPED, dd/mkfs harden, CGNAT/userinfo SSRF,
cache wall-clock TTL + hashed paths, broadened .env skips, generic-handler validation.

Goal status: production gates must stay green (`mypy` + full non-e2e pytest). Absolute “every
possible bug / most-powerful product forever” is not a finite claim — known SX + hunt P0/P1
items are closed with tests; further polish can continue without blocking production use.
