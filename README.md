# atHome

atHome is a local-first identity and routing protocol for human-owned AI agents, services, and delegated capabilities. Each person owns a signed root identity (for example `krav@atHome`), attaches services (`agent@krav`) and agents (`foreman@krav`), issues scoped capability tokens, and verifies signed requests before any service acts. Authority stays local, explicit, signed, and revocable.

Project links: [Changelog](CHANGELOG.md) · [Security Policy](SECURITY.md) · [Contributing and governance](CONTRIBUTING.md) · [License](LICENSE)

## Status

The atHome protocol implementation (`packages/protocol`, `apps/api`, `packages/sdk`, `apps/web`) is the mature part of this repository and is suited to local development and protocol iteration. It is not a production distributed registry or production key-custody service. See the [Changelog](CHANGELOG.md) for what is released versus unreleased.

The A1 packages listed below are **provisional contracts**. They are additive, do not replace `IdentityManifest` or `CapabilityToken`, and may change.

## Quickstart

```bash
git clone https://github.com/ao3575911/atHome.git
cd atHome
npm install
npm run dev     # API at http://127.0.0.1:3000
npm run demo    # offline end-to-end protocol demo
```

With the API running: Swagger UI at `/docs`, OpenAPI JSON at `/openapi.json`, health at `/health`. Optional configuration starts from `.env.example`; export values in your shell (`.env.local` is not auto-loaded).

## Commands

```bash
npm run dev            # start the Fastify API
npm run demo           # run the protocol demo
npm run dev:web        # Next.js dev server
npm run typecheck      # TypeScript check (packages, API, scripts, examples)
npm run typecheck:web  # web TypeScript check
npm test               # Vitest suite
npm run lint           # Prettier check (npm run format to fix)
npm run audit:high     # npm audit, high severity and above
npm run build:web      # production web build
npm run generate:sdk   # regenerate OpenAPI schema-name pinning
```

See [Operational Gates](docs/operational-gates.md) for the full verification list.

## Architecture

```text
apps/api         Fastify REST API over the protocol
apps/web         Next.js platform (public, developer, ops surfaces)
packages/protocol  Crypto, signing, policy, registry, storage backends
packages/sdk     Typed HTTP client and mutation signers
data/            Local dev storage (demo fixtures; private keys gitignored)
docs/ schemas/ examples/ scripts/
```

`packages/protocol` is the source of truth; the API and SDK delegate to it. Storage backends: local JSON, SQLite, and Postgres.

### Provisional A1 packages

| Package                   | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `@athome/identity-core`   | A1 identity keys, canonical bytes, Ed25519 signing interfaces  |
| `@athome/creator-proof`   | Local proof validation with trust-anchor and revocation checks |
| `@athome/registry-client` | Typed remote lookup with explicit failure states               |
| `@athome/cli`             | Public-key onboarding and proof/registry verification          |

A1 trust is always anchored in caller-supplied local trust anchors; a registry response alone never establishes trust. See the [A1 migration guide](docs/migration/a1-identity-trust-consolidation.md), the [ADR](docs/adr/0001-a1-canonical-identity-signature-envelope.md), and `schemas/`.

## Security boundary

- `POST /identities` is a local-development bootstrap path and is blocked in production.
- Other mutating routes require a signed `X-Home-Authorization` header; the SDK provides signers (`createRootMutationSigner`, `createWebCryptoMutationSigner`, `createExternalMutationSigner`, `createPasskeyMutationSigner`).
- `ATHOME_DEMO_PRIVATE_KEY_EXPORT=true` is for local demos only; startup fails if it is set with `NODE_ENV=production`.
- Production must not return private keys; use passkeys/WebAuthn, client-side signing, KMS, HSM, or another reviewed custody boundary.
- Demo private keys committed in early history are compromised; see [SECURITY.md](SECURITY.md).

## Documentation and examples

- [API Cheat Sheet](docs/cheatsheet.md)
- [Protocol Signing](docs/protocol-signing.md)
- [Distributed Revocation Model](docs/distributed-revocation-model.md)
- [Key Custody Plan](docs/key-custody-plan.md)
- [Transparency and Audit Log](docs/transparency-and-audit-log.md)
- [Threat Model](docs/threat-model/README.md)
- [Hosted Registry Architecture](docs/specs/v0.3-hosted-registry-architecture.md)
- [Production Key Custody](docs/specs/v0.3-production-key-custody.md)
- [Roadmap and release notes](docs/roadmap/v0.3-build-plan-spec.md), [releases](docs/releases/)
- Examples: [`examples/`](examples/) (SDK usage, demo, external/passkey signers, root rotation)

## Contributing

Conventional Commit titles, the label taxonomy, and verification gates are described in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
