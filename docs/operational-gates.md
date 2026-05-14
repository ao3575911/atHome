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

## Current Known Gate Blockers

As of May 13, 2026, `npm audit --audit-level=high` reports existing advisories outside the SDK/web integration ownership slice:

- `fast-uri` high-severity advisories through the Fastify dependency chain in `apps/api`.
- moderate advisories through `vitest`/`vite` and `next`/`postcss`.

The Fastify remediation requires an `apps/api` dependency update, which is intentionally outside the SDK/web/docs ownership for this pass.

`npm run lint` may also fail until the pre-existing formatting drift in `packages/protocol/src/registry.ts`, `packages/protocol/test/protocol.test.ts`, and `README.md` is handled by the owners of those files.
