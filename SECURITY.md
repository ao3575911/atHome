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

## Production Boundary

Production deployments should disable bootstrap private-key export, avoid server-returned private keys, and use an explicit custody layer such as passkeys/WebAuthn, client-side signing, KMS, HSM, or another reviewed signing boundary.
