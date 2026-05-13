# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

atHome is a local-first identity and routing protocol for AI agents. The core concept: each person owns a signed root identity (`krav@home`), attaches services and agents to it, issues scoped capability tokens, and verifies signed requests before any service acts. Authority stays local, explicit, signed, and revocable.

## Commands

```bash
npm install              # install all workspace deps
npm run dev              # start Fastify API on http://127.0.0.1:3000
npm run demo             # run offline end-to-end protocol demo
npm test                 # Vitest test suite (all packages)
npm run test:watch       # watch mode
npm run typecheck        # TypeScript check (excludes apps/web)
npm run lint             # Prettier check
npm run format           # Prettier write

# Run a single test file
npx vitest run apps/api/test/app.test.ts

# Web platform
npm run dev:web          # Next.js dev server
npm run build:web        # production build
npm run typecheck:web    # web-only TS check

# Demo with private key export (dev only)
ATHOME_DEMO_PRIVATE_KEY_EXPORT=true npm run dev
```

## Monorepo layout

```
packages/protocol    Core protocol primitives — all crypto, signing, policy, storage
packages/sdk         Thin fetch client wrapping the HTTP API
apps/api             Fastify HTTP server that exposes protocol over REST
apps/web             Next.js App Router web platform (public, developer, ops surfaces)
scripts/             Demo runner and OpenAPI schema-name generator
examples/            Developer usage examples
data/                Local JSON storage (manifests, revocations, events, witness receipts)
docs/                Protocol design docs and roadmap specs
```

## Architecture: how the layers connect

`packages/protocol` is the source of truth. Everything else calls into it:

- `apps/api/src/app.ts` — builds the Fastify app, wires Zod parsing and `requireMutationAuthorization`, delegates all business logic to `IdentityRegistry` from `@home/protocol`
- `packages/protocol/src/registry.ts` — top-level orchestrator; owns `createIdentity`, `registerService`, `registerAgent`, `issueCapabilityToken`, `verifyCapability`, `verifyRequest`, `resolve`, `revokeAgent/Token/Key`, `rotateRootKey`
- `packages/protocol/src/store.ts` / `sqlite-store.ts` — two storage backends (local JSON files, SQLite); registry takes either via `RegistryBackend`
- `packages/sdk/src/client.ts` — wraps every API endpoint as typed methods; exposes `createRootMutationSigner(privateKeyHex)` to build `X-Home-Authorization` headers automatically

Key protocol modules in `packages/protocol/src/`:

| File               | Purpose                                               |
| ------------------ | ----------------------------------------------------- |
| `crypto.ts`        | Ed25519 keygen, sign, verify, nonce                   |
| `canonical.ts`     | Deterministic JSON serialization for signing          |
| `manifest.ts`      | Identity manifest create/sign/verify                  |
| `capabilities.ts`  | Capability token issue/verify                         |
| `request.ts`       | Signed agent request create/verify                    |
| `mutation-auth.ts` | `X-Home-Authorization` header create/verify           |
| `policy.ts`        | Route → permission mapping, deny-rule evaluation      |
| `resolver.ts`      | Name resolution (`agent@krav` → root manifest lookup) |
| `revocations.ts`   | Revocation index read/write                           |
| `events.ts`        | Append-only registry event log                        |
| `witness.ts`       | Witness receipt creation                              |
| `store.ts`         | `LocalJsonStore` — file-based storage backend         |
| `sqlite-store.ts`  | SQLite storage backend (in progress)                  |

## Mutating routes require signed authorization

All API routes that mutate state (except `POST /identities` bootstrap) require an `X-Home-Authorization` header signed by the identity's root key over `method + path + body`. The SDK's `createRootMutationSigner` handles this. See `apps/api/src/app.ts:requireMutationAuthorization` and `packages/protocol/src/mutation-auth.ts`.

## TypeScript configuration

`tsconfig.json` at root covers `apps/`, `packages/`, `scripts/`, `examples/` with strict mode, `NodeNext` module resolution, and `exactOptionalPropertyTypes`. `apps/web` has its own tsconfig (excluded from root). All packages are ESM (`"type": "module"`); imports within packages use `.js` extensions even for `.ts` source files.

## Storage layout

`data/` is the local dev storage root (overridable via `DATA_DIR`):

```
data/manifests/      Public signed manifests (tracked as demo fixtures)
data/private/        Private key records (gitignored; .gitkeep only)
data/revocations/    Revocation indexes
data/events/         Append-only registry events
data/witness/        Witness receipts
data/replay.json     Nonce replay cache (gitignored runtime state)
```

## Key production boundaries (never violate in code)

- `ATHOME_DEMO_PRIVATE_KEY_EXPORT=true` is rejected when `NODE_ENV=production`
- `POST /identities` bootstrap is blocked in production
- Private keys must never appear in production API responses
- The API server generates keys server-side only for local dev; production must use client-side/KMS/HSM custody

## Test files

```
apps/api/test/app.test.ts          HTTP integration tests via Fastify inject
apps/api/test/hardening.test.ts    Production-hardening and security edge cases
packages/protocol/test/protocol.test.ts   Full protocol flow unit tests
packages/protocol/test/backend.test.ts    Storage backend tests
packages/protocol/test/sqlite-store.test.ts  SQLite store tests
packages/sdk/test/client.test.ts   SDK client tests
```
