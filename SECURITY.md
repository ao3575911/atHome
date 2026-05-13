# Security Policy

`atHome` is currently a developer implementation for local protocol iteration. It is not yet a production distributed registry or production key-custody service.

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
