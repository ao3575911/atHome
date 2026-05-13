# Security Policy

`` is currently a developer implementation for local protocol iteration. It is not yet a production distributed registry or production key-custody service.

## Supported Scope

Security review is welcome for:

- protocol signing and canonicalization
- mutation authorization
- capability-token verification
- revocation semantics
- local storage boundaries
- demo/private-key export controls
- SDK request signing helpers
- web-platform data exposure and mock-data boundaries

## Reporting a Vulnerability

Please open a private security advisory if available, or file an issue with minimal sensitive detail and a request to move details privately.

Do **not** post live private keys, production secrets, personal data, or exploit payloads that target third-party systems.

## Demo Key Material

Local demo private-key records under `data/private/` are intentionally gitignored. If demo keys were ever published in repository history, treat them as compromised samples and rotate/regenerate any affected data before using the repository as a base for real deployments.

### Historical Key Compromise Boundary

Demo private-key records for the following identities were committed to repository history in commit `9b935f8` (uploaded 2026-05-11) and deleted in commit `1986ff6` (organized 2026-05-13):

- `alice@home` (root key and `assistant@alice#agent` key)
- `api@home` (root key)
- `krav-admin@home` (root key)
- `krav@home` (root key and `foreman@krav#agent` key)

These keys are permanently exposed in repository history and must be treated as compromised. They **must not** be used for any real deployment, trust anchor, or non-demo purpose. The public manifests under `data/manifests/` that correspond to these keys are retained as inspectable demo fixtures only.

A full history rewrite was evaluated and declined to avoid disrupting existing clones and forks. The compromise boundary is instead documented here explicitly.

If you have cloned this repository before 2026-05-13, regenerate all demo data before using it as a trust anchor.

## Production Boundary

Production deployments should disable bootstrap private-key export, avoid server-returned private keys, and use an explicit custody layer such as passkeys/WebAuthn, client-side signing, KMS, HSM, or another reviewed signing boundary.

## NPM Audit — v0.3.0-alpha2

Audited 2026-05-13. High-severity advisories resolved; 7 moderate remain. All require breaking dependency changes and are documented below as accepted risk.

### Resolved

| Advisory            | Package                   | Fix applied                                                         |
| ------------------- | ------------------------- | ------------------------------------------------------------------- |
| GHSA-q3j6-qgpj-74h6 | fast-uri / fastify ≤5.8.2 | Upgraded fastify 4→5, @fastify/swagger 8→9, @fastify/swagger-ui 4→5 |
| GHSA-v39h-62p7-jpjc | fast-uri / fastify ≤5.8.2 | Same as above                                                       |

### Accepted risk — awaiting upstream fixes

**GHSA-67mh-4wv8-2f99 · esbuild ≤0.24.2 (moderate)**
Affects `vitest@2.x` → `vite` → `esbuild`. The vulnerability allows a website to proxy requests to the esbuild dev server during development. Fixing requires upgrading vitest 2→4 which is a major breaking change in the test harness. Risk is confined to local developer machines running `npm test` or `npm run dev`; it has no surface in CI (headless) or in any deployed environment. Accepted until vitest 4.x migration is scheduled.

**GHSA-qx2v-qp2m-jg93 · postcss < 8.5.10 (moderate)**
Affects `next@15.x` which bundles its own postcss. The XSS involves unescaped `</style>` tags in PostCSS CSS-serialization output. npm audit suggests `next@9.3.3` as a fix, which is an unusable 6-major-version downgrade; the correct resolution is a Next.js patch that updates its internal postcss. Risk is in the build toolchain/CSS processing pipeline, not in runtime HTTP responses or the protocol layer. Accepted until Next.js 15.x ships postcss ≥8.5.10.
