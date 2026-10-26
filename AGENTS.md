# AGENTS.md

Instructions for coding agents working in this repository. Humans: see [CONTRIBUTING.md](CONTRIBUTING.md). Architecture notes: [CLAUDE.md](CLAUDE.md).

## Setup

Node.js 22 or later (the SQLite backend uses the built-in `node:sqlite`).

```sh
npm ci
```

## Checks (the CI `test` job runs all of these)

```sh
npm run lint            # Prettier
npm run typecheck       # packages, apps/api, scripts, examples
npm run typecheck:web   # apps/web
npm test                # Vitest
npm run audit:high      # npm audit, high and above
npm run build:web       # Next.js production build
```

Run `npm run format` before committing.

## Layout

- `packages/protocol`: source of truth for crypto, signing, policy and storage. Everything else calls into it.
- `packages/sdk`: typed HTTP client. `apps/api`: Fastify server. `apps/web`: Next.js site.
- `packages/identity-core`, `creator-proof`, `registry-client`, `cli`: provisional A1 contracts. Do not change existing signed formats to fit them.
- `schemas/`: JSON Schema contracts. `docs/`: design notes, ADRs and threat model.

## Rules

- Never return private keys from production code paths. `hardening.test.ts` must keep passing.
- Signed formats (manifests, tokens, requests, `X-Home-Authorization`) change only with a version bump, a migration note and tests.
- Add a CHANGELOG entry under Unreleased (Keep a Changelog).
- Conventional Commit PR titles (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`); they become the squash commit and drive Release Please.
- Pin actions to a version and keep workflow permissions at `contents: read` unless a job needs more.
- `main` is protected: open a PR, `test` must pass, squash merge, signed commits.
- No placeholder text and no marketing language.
