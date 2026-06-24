# Repository Migration Announcement

**Date:** June 2026

I have some exciting news to share — Siyarix will soon be moving to its new home.

## What is happening?

The Siyarix repository will migrate from my personal repo `mufthakherul/siyarix` to **`siyarix/siyarix`** — a dedicated GitHub organization created for the project. Alongside this, the project documentation and community hub will move to **`siyarix/siyarix.github.io`**, which will serve as the central information center for everything Siyarix.

## Why the move?

What began as a personal project has grown into something far larger than one person could build alone. It became clear that Siyarix needed its own space — an organizational structure that can better support collaboration, governance, and long-term sustainability.

This move reflects my commitment to:

- **Community ownership** — The project belongs to its community, not a single individual. An organization structure ensures no single point of failure and invites broader participation.
- **Transparent governance** — An organizational framework allows for clearer decision-making, defined roles, and structured contribution pathways.
- **Long-term stability** — Separation from any one person's account ensures continuity regardless of circumstances, safeguarding the project's future.
- **Professional identity** — A dedicated organization presents Siyarix as the serious, production-grade platform it has become — one that enterprises and security professionals can trust and rely upon.

## What does this mean for you?

| For | Impact |
|-----|--------|
| **Users** | Minimal — once migrated, simply update your `git remote` URL. Everything else stays the same: same code, same license (AGPL-3.0-or-later), same mission, same commitment to quality. |
| **Contributors** | Your forks will need to be re-forked from the new organization, or you can update the remote URL of your existing clone. All contribution guidelines remain unchanged. |
| **Issue & PR authors** | GitHub will automatically redirect to the new location — no action is needed on your part. Your contributions will remain visible and attributed. |
| **Stars & watchers** | These will not transfer automatically. We warmly invite you to visit the new repository and give it a star if you believe in what we are building. |

## Migration steps

### If you are a user (cloning or pulling)

Once the migration is complete:

```bash
git remote set-url origin https://github.com/siyarix/siyarix.git
```

### If you have a fork

```bash
git remote add upstream https://github.com/siyarix/siyarix.git
git remote set-url origin https://github.com/YOUR-USERNAME/siyarix.git
```

## Timeline

| Date | Milestone |
|------|-----------|
| June 2026 | Announcement of planned migration |
| TBD | Repository transfer — date to be confirmed |

## What is not changing

- All existing releases, tags, and branches remain intact
- The PyPI package will continue to work — the homepage URL will be updated in the next release
- The documentation (available at `siyarix.github.io`) will be kept up to date
- Our commitment to the AGPL-3.0-or-later license and ethical use policy remains unchanged
- The project's direction, values, and quality standards remain exactly as they have always been

## A personal note

When I started Siyarix, I had a simple idea: what if security tools could understand plain English? What if we could tell a computer what we wanted to accomplish, rather than how to do it step by step?

That idea has grown beyond anything I could have imagined, thanks to every person who has used the tool, filed an issue, submitted a pull request, or simply shared the project with a colleague. This upcoming move is not about leaving the old behind — it is about creating a foundation sturdy enough to support what comes next.

Siyarix belongs to all of us now. Let us build the future of security operations together.

**Thank you for being part of this journey.**

— MD Mufthakherul Islam Miraz
  Path Maker, Siyarix

---

*Questions, concerns, or suggestions? Please open a discussion in the new repository or reach out through the project's communication channels.*
