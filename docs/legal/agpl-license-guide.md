# AGPL-3.0-or-later License Guide

Siyarix is distributed under the **GNU Affero General Public License v3.0 or later** (SPDX: `AGPL-3.0-or-later`).

## What AGPL-3.0 means

The AGPL-3.0 is a free software license published by the Free Software Foundation. It combines the GNU GPL v3 with an additional provision addressing:

### Key rights

You are free to:

- **Use**: Run Siyarix for any purpose
- **Study**: Examine the source code to understand how it works
- **Modify**: Change the code to suit your needs
- **Share**: Redistribute copies to others
- **Improve**: Release your improvements to the public

### Key conditions

If you distribute Siyarix (or a modified version) to others, you must:

1. **Provide source code**: Make the complete source code available
2. **License under AGPL-3.0**: Your distribution must be under AGPL-3.0 or later
3. **State changes**: Document any modifications you made
4. **Include license notice**: Keep the original copyright and license notices
5. **No additional restrictions**: Do not add further restrictions on recipients

### Network use clause

The AGPL-3.0 adds a network use provision (Section 13):

> If you run a modified version of the program over a network and users interact with it, you must make the source code available to those users.

This means if you deploy Siyarix as a service that users interact with over a network, you must provide access to the source code (including any modifications).

## AGPL-3.0-only vs AGPL-3.0-or-later

Siyarix uses the "or later" variant:

| Variant | Meaning |
|---------|---------|
| AGPL-3.0-only | Licensed only under version 3.0. If FSF releases AGPL v4, you must use v3. |
| AGPL-3.0-or-later | Licensed under version 3.0 or any later version published by FSF. |

Using "or later" means the project can adopt future FSF license versions without re-licensing.

## What this means for you

### Individual users

You can use Siyarix for any legitimate purpose — security testing, research, learning — without restrictions. No license fees, no registration.

### Organizations

- **Internal use**: You can use Siyarix internally without distributing the source
- **Service deployment**: If you run Siyarix as a network service, you must make the source (including modifications) available to users
- **Distribution**: If you distribute Siyarix as part of a product, the entire product must be AGPL-3.0 compatible

### Developers

- **Contributing**: By contributing to Siyarix, you agree to license your contributions under AGPL-3.0-or-later
- **Modifications**: Changes must be shared when distributed
- **Bundling**: You can combine Siyarix with other AGPL-compatible software

## Compatibility

AGPL-3.0 is compatible with:

- **GPL-3.0**: Can combine AGPL code with GPL-3.0 code
- **Apache-2.0**: Compatible (Apache-2.0 code can be included in AGPL project)
- **MIT, BSD, ISC**: Compatible (permissive licenses can be included in AGPL project)
- **CC0**: Compatible (public domain dedication)

AGPL-3.0 is NOT compatible with:

- **GPL-2.0**: Cannot combine AGPL-3.0 code with GPL-2.0 code
- **Proprietary licenses**: AGPL code cannot be incorporated into proprietary software

## Full license text

The complete license text is in the [LICENSE](../../LICENSE) file at the project root.

## Additional legal documents

- [NOTICE](../../NOTICE) — Copyright notices and third-party attributions
- [DISCLAIMER](../legal/disclaimer.md) — Warranty disclaimer and liability limitation
- [ETHICAL_USE.md](../../ETHICAL_USE.md) — Permitted and prohibited use
- [RESPONSIBLE_AI_USE.md](../../RESPONSIBLE_AI_USE.md) — AI-specific governance
