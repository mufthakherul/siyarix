# AGPL-3.0-or-later License Guide

Siyarix is distributed under the **GNU Affero General Public License v3.0 or later** (SPDX: `AGPL-3.0-or-later`).

## What AGPL-3.0 means

The AGPL-3.0 is a free software license published by the Free Software Foundation. It combines the GNU GPL v3 with an additional network use provision.

### Key rights

You are free to:

- **Use**: Run Siyarix for any purpose
- **Study**: Examine the source code
- **Modify**: Change the code to suit your needs
- **Share**: Redistribute copies
- **Improve**: Release improvements to the public

### Key conditions

If you distribute Siyarix (or a modified version) to others, you must:

1. **Provide source code**: Make the complete source code available
2. **License under AGPL-3.0**: Your distribution must be under AGPL-3.0 or later
3. **State changes**: Document any modifications you made
4. **Include license notice**: Keep original copyright and license notices
5. **No additional restrictions**: Do not add further restrictions on recipients

### Network use clause (Section 13)

> If you run a modified version of the program over a network and users interact with it, you must make the source code available to those users.

This means if you deploy Siyarix as a network service, you must provide source access (including modifications) to users.

## AGPL-3.0-only vs AGPL-3.0-or-later

| Variant | Meaning |
|---------|---------|
| AGPL-3.0-only | Licensed only under v3.0. If FSF releases AGPL v4, you must use v3. |
| AGPL-3.0-or-later | Licensed under v3.0 or any later version published by FSF. |

"or later" allows the project to adopt future FSF license versions without re-licensing.

## What this means for you

### Individual users
Use Siyarix for any legitimate purpose — security testing, research, learning — without restrictions. No license fees, no registration.

### Organizations
- **Internal use**: Use internally without distributing source
- **Service deployment**: If running as a network service, make source (including modifications) available to users
- **Distribution**: If distributed as part of a product, the entire product must be AGPL-3.0 compatible

### Developers
- **Contributing**: Contributions are licensed under AGPL-3.0-or-later
- **Modifications**: Changes must be shared when distributed
- **Bundling**: Can combine with other AGPL-compatible software

## Plugin exception

Third-party plugins loaded dynamically via `~/.siyarix/plugins/` are exempt from AGPL requirements. They may use any license (including proprietary). See [Plugin Exception](plugin-exception.md).

## Compatibility

AGPL-3.0 is compatible with:
- **GPL-3.0**: Can combine AGPL code with GPL-3.0 code
- **Apache-2.0**: Apache-2.0 code can be included in AGPL projects
- **MIT, BSD, ISC**: Permissive licenses can be included in AGPL projects
- **CC0**: Public domain dedication

AGPL-3.0 is NOT compatible with:
- **GPL-2.0**: Cannot combine AGPL-3.0 code with GPL-2.0 code
- **Proprietary licenses**: AGPL code cannot be incorporated into proprietary software

## Full license text

The complete license text is in the project LICENSE file.

## Additional legal documents

- NOTICE — Copyright notices and third-party attributions
- [Disclaimer](disclaimer.md) — Warranty disclaimer and liability limitation
- [Responsible AI Usage](responsible-ai-usage.md) — AI-specific governance
