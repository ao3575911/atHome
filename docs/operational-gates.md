# Operational Gates

This repository treats SDK helpers, API contracts, and web integration as one release surface. Use these gates before opening or merging changes.

## Required Local Gates

Run from the repository root:

```bash
npm run typecheck
npm run typecheck:web
npm test
npm run lint
npm run audit:high
npm run build:web
```

## Web/API Integration Gate

The web app reads the API base URL from `ATHOME_API_BASE_URL`, then `NEXT_PUBLIC_ATHOME_API_BASE_URL`, and falls back to `http://127.0.0.1:3000`.

For live local verification:

```bash
npm run dev
ATHOME_API_BASE_URL=http://127.0.0.1:3000 npm run dev:web
```

Then verify:

- `/status` shows `Registry API` from live `/health`.
- `/developer/playground?name=krav@atHome` resolves through live `POST /resolve`.
- If the API is offline, the same pages must say `Demo fallback` or `fallback` instead of presenting mock data as live data.

## CI Gate

GitHub Actions runs the same package checks:

- root TypeScript typecheck
- web TypeScript typecheck
- Vitest suite
- Prettier check
- high-severity npm audit
- production web build

For hosted-registry durability validation, run the same `Verify` workflow via `workflow_dispatch` with `run_hosted_postgres=true` and secret `ATHOME_VERIFY_DATABASE_URL`.

Do not merge around a failing gate without documenting the failure, owner, and remediation path.

## Current Verification

The authoritative, current checks are the commands listed under Required Local Gates and the `Verify` workflow. `npm run audit:high` runs `npm audit --audit-level=high`; the root `package.json` `overrides` pin patched transitive dependencies. A failing gate is a current blocker; record the exact output when reporting one.

Pull requests also run the `Dependency Review` workflow, which flags newly introduced vulnerable dependencies.

## Historical Context

As of May 13, 2026, `npm audit --audit-level=high` reported `fast-uri` high-severity advisories through the Fastify chain in `apps/api`. These were resolved by the Fastify 5 upgrade (see [SECURITY.md](../SECURITY.md)) and are retained only as history. Moderate advisories (`vitest`/`vite`, `next`/`postcss`) are tracked as accepted risk in [npm-audit-v0.3.md](security/npm-audit-v0.3.md); they do not fail `audit:high`.

## Maintainer Runbook (GitHub administration)

Repository files cannot change GitHub settings. Maintainers must follow up manually:

- Synchronize labels from `.github/labels.yml` through repository settings or the GitHub API/CLI.
- Standardize existing issues and PRs using the taxonomy in [CONTRIBUTING.md](../CONTRIBUTING.md).
- GitHub Discussions do not support labels the same way as issues/PRs; use discussion categories instead.
- Delete the remote branch `cursor/athome-review-deliverables-f616` only after confirming it has no unmerged work.
- Existing commit history is intentionally not rewritten (see SECURITY.md).
