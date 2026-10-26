# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Parallel verification of one signed request could accept it more than once; the nonce check and record now run under a per-nonce lock (#62).
- `LocalJsonStore` no longer fails with `ENOENT` or drops nonces under concurrent writes (#63).

## [0.4.0] - 2026-10-26

### Added

- CI workflow with a required `test` job (Prettier, offline link check, typecheck, tests, audit, builds), CodeQL, Dependabot for npm and GitHub Actions, and label sync from `.github/labels.yml`.
- Tag-triggered Release workflow: publishes `@athome/protocol` and `@athome/sdk` to npm through trusted publishing with provenance, then creates the GitHub release from this file. Manual-dispatch Release Please proposes the next version.
- Compiled `dist/` builds for `@athome/protocol` and `@athome/sdk`.
- `AGENTS.md`, `CODE_OF_CONDUCT.md`, Copilot instructions and `.github/settings.yml`.

- A1 identity/trust boundary packages (provisional): `@athome/identity-core`, `@athome/creator-proof`, `@athome/registry-client`, and `@athome/cli`, with JSON schemas under `schemas/` and migration notes in `docs/migration/a1-identity-trust-consolidation.md`.
- `CHANGELOG.md`, `CONTRIBUTING.md` (Conventional Commit and PR-title conventions, label taxonomy), and `.github/labels.yml`.
- `Dependency Review` GitHub Actions workflow for pull requests.

### Changed

- README rewritten as a durable entry point separating the atHome protocol implementation from provisional A1 contracts.
- Issue and pull-request templates prompt for taxonomy labels, verification, and security impact.
- `Verify` workflow uses least-privilege permissions and concurrency control.
- `docs/operational-gates.md` distinguishes current verification from historical audit context.

### Fixed

- Missing product name in `SECURITY.md`, the API startup log message, and the web page title.

## [0.3.0] - 2026-05-14

### Added

- `PostgresRegistryBackend` with SQL migrations and a backend parity suite run against memory, local JSON, SQLite and Postgres.
- Namespace lifecycle endpoints: reserve, transfer, recover, suspend and restore.
- `PasskeyKeyCustodyProvider`, an HSM custody interface and a KMS adapter skeleton; `createPasskeyMutationSigner` in the SDK.
- Identity recovery ceremony that produces a signed root-key rotation event.
- Developer playground for signed mutations, ops admin auth and live audit, health and status panels in the web app.

## [0.3.0-alpha2] - 2026-05-14

### Added

- `KeyCustodyProvider` abstraction with a local development provider.
- Root key rotation endpoint and SDK helper.
- External, WebCrypto and root mutation signers.
- SQLite storage backend using `node:sqlite`.
- Next.js web platform wired to the API.

### Security

- Startup fails when `ATHOME_DEMO_PRIVATE_KEY_EXPORT=true` is set with `NODE_ENV=production`; private keys are never returned in production responses.

## [0.1.0] - 2026-05-13

### Added

- First tagged release: signed identity manifests, capability tokens, signed requests, revocations, Fastify API, SDK and repository governance files.

[Unreleased]: https://github.com/ao3575911/atHome/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ao3575911/atHome/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ao3575911/atHome/compare/v0.3.0-alpha2...v0.3.0
[0.3.0-alpha2]: https://github.com/ao3575911/atHome/compare/v0.1.0...v0.3.0-alpha2
[0.1.0]: https://github.com/ao3575911/atHome/releases/tag/v0.1.0
