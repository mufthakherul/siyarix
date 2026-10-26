# Siyarix v1.2.0 — Production-readiness & operator-safety

**Date:** 2026-10-26 (Asia/Dhaka)
**Version:** 1.2.0

## Summary

Siyarix v1.2.0 packages the production-readiness hardening track for the next Beta
cut: operator-safety residual hunter waves RH-01–RH-55, CLI modularization, chat
UI theme polish, and readiness scoring that does not penalize optional LLM
provider gaps.

## Highlights

- Engagement scope (`SIYARIX_ALLOWED_SCOPE`) remains optional; when set, ssh
  `HostName=`, parallel `-S`, ansible/fab/lxc/virsh peers, and additional URI
  schemes are engagement-bound.
- Destructive hard-blocks cover UID-0 account pivots and
  `update-alternatives --install` on system binaries.
- Dotenv guard skips Kerberos/SSSD/LDAP/SSH host pivots from planted `.env`.
- Chat welcome banner uses active theme design tokens.
- `siyarix production-check` / `doctor` exercise RH-55 probes.

## Upgrade notes

- Bump package installs to `1.2.0`; no settings schema break expected.
- Production deployments should set a master password vault and review
  `SIYARIX_TRUST_PLUGINS` (prefer unset; `=force` only for reviewed plugins).
- Optional: set `SIYARIX_ALLOWED_SCOPE` for engagement-bound automation.

## Known follow-ups (non-blocking)

- SX-A01: `register_tools` remains in-process (OS isolation optional via bwrap).
- Residual hunter waves continue post-tag for new tool surfaces.
