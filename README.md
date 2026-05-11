# atHome

`atHome` is a local-first identity and agent-routing protocol for humans, services, and AI agents.

It lets a person own a signed root identity such as `krav@home`, attach services such as `agent@krav` or `inbox@krav`, register delegated agents such as `foreman@krav`, issue scoped capability tokens, and verify signed agent requests before any service takes action.

## Current Status

This repository is the v0.2 developer implementation:

- signed identity manifests
- deterministic canonical JSON signing
- Ed25519 keys and signatures
- service and agent resolution
- explicit authorization policy checks
- audience-scoped capability tokens
- signed request verification
- nonce/replay protection
- local JSON-backed manifests, private records, revocations, events, and witness receipts
- generated OpenAPI JSON at `/openapi.json`
- Swagger UI at `/docs`
- TypeScript SDK client with root mutation-signing helpers
- local demo and test suite

The project is ready for local development and protocol iteration. It is not yet a production distributed registry or production key-custody system.

## Quickstart

### 1. Install

```bash
cd ~/Desktop/@home/@home
pnpm install
```

### 2. Configure environment

Optional local configuration starts from the checked-in template:

```bash
cp .env.example .env.local
```

The dev command does not auto-load `.env.local`; export values in your shell when needed.

### 3. Start the API

For local demo use:

```bash
ATHOME_DEMO_PRIVATE_KEY_EXPORT=true pnpm dev
```

The API runs at:

```text
http://127.0.0.1:3000
```

Open:

- Swagger UI: <http://127.0.0.1:3000/docs>
- OpenAPI JSON: <http://127.0.0.1:3000/openapi.json>
- Health check: <http://127.0.0.1:3000/health>

### 4. Run the demo

```bash
pnpm demo
```

The demo creates identities, registers services and agents, issues capability tokens, verifies allowed requests, rejects denied requests, checks audience mismatch, and proves revocation behavior.

### 5. Run verification gates

```bash
pnpm typecheck
pnpm test
```

## Copy-Paste Usage Guide

Use the full API cheat sheet for end-to-end registration and verification commands:

- [API Cheat Sheet](docs/cheatsheet.md)

It includes copy-paste commands for:

- starting the API
- creating a root identity
- generating signed mutation authorization headers
- registering services
- registering agents
- issuing capability tokens
- resolving names
- verifying capability tokens
- creating signed agent requests
- verifying requests
- revoking tokens, agents, and keys

## Full Documentation

Protocol and production-hardening docs live in `docs/`:

- [API Cheat Sheet](docs/cheatsheet.md)
- [Protocol Signing](docs/protocol-signing.md)
- [Distributed Revocation Model](docs/distributed-revocation-model.md)
- [Production Key Custody Plan](docs/key-custody-plan.md)
- [Transparency and Audit Log Model](docs/transparency-and-audit-log.md)

Examples live in `examples/`:

- [SDK Usage Example](examples/sdk-usage.ts)
- [Demo Example](examples/demo.ts)

## Web platform

The monorepo now includes a production-oriented Next.js App Router web platform in `apps/web` with three surfaces:

- Public site: `/`, `/pricing`, `/namespace`, `/docs`, `/status`
- Developer portal: `/developer`, `/developer/keys`, `/developer/playground`, `/developer/webhooks`, `/developer/sdks`, `/developer/docs`
- Internal ops panel: `/ops`, `/ops/users`, `/ops/namespaces`, `/ops/audit`, `/ops/abuse`, `/ops/health`

Run it locally:

```bash
pnpm dev:web
pnpm build:web
pnpm typecheck:web
```

The UI uses Next.js, TypeScript, Tailwind CSS, shadcn-style primitives, lucide-react icons, masked mock data, dark mode, and modular component/data layers under `apps/web/components` and `apps/web/lib`.

## Architecture

This is a pnpm monorepo:

```text
apps/api              Fastify API server
packages/protocol     Protocol primitives, signing, policy, registry, storage
packages/sdk          Fetch-based TypeScript SDK
scripts/demo.ts       End-to-end offline demo
scripts/generate-sdk.ts OpenAPI schema-name pinning helper
examples/             Developer examples
docs/                 Protocol and production design docs
data/                 Local demo storage
```

### Protocol package

`packages/protocol` owns:

- canonical JSON serialization
- Ed25519 signing and verification
- identity manifest creation and verification
- service and agent definitions
- capability token issuance and verification
- signed request creation and verification
- route-to-permission mapping
- mutation authorization signing
- revocation records
- append-only registry events
- witness receipts
- local JSON and memory storage backends

### API package

`apps/api` exposes the protocol over HTTP with Fastify.

Core endpoints:

| Method | Path                                                | Purpose                          |
| ------ | --------------------------------------------------- | -------------------------------- |
| `GET`  | `/health`                                           | API health check                 |
| `GET`  | `/openapi.json`                                     | Generated OpenAPI document       |
| `GET`  | `/docs`                                             | Swagger UI                       |
| `POST` | `/identities`                                       | Dev bootstrap identity creation  |
| `GET`  | `/identities/:id`                                   | Fetch public manifest            |
| `POST` | `/identities/:id/services`                          | Register service endpoint        |
| `POST` | `/identities/:id/agents`                            | Register delegated agent         |
| `POST` | `/identities/:id/capability-tokens`                 | Issue capability token           |
| `POST` | `/identities/:id/agents/:agentId/revoke`            | Revoke agent                     |
| `POST` | `/identities/:id/capability-tokens/:tokenId/revoke` | Revoke capability token          |
| `POST` | `/identities/:id/keys/:keyId/revoke`                | Revoke public key                |
| `POST` | `/resolve`                                          | Resolve root/service/agent names |
| `POST` | `/verify/capability`                                | Verify a capability token        |
| `POST` | `/verify/request`                                   | Verify a signed agent request    |

Mutating routes, except local bootstrap identity creation, require an `X-Home-Authorization` header signed by the root key over the exact method, path, and request body. See the [API Cheat Sheet](docs/cheatsheet.md#3-helper-create-signed-mutation-authorization-headers).

## Identity Model

A root identity such as `krav@home` publishes a signed manifest containing:

- public keys
- service endpoints
- registered agents
- optional claims
- optional recovery methods
- signature metadata

The manifest signature is generated over canonical JSON with the `signature` field excluded. This makes manifests reproducible and independently verifiable.

## Service and Agent Resolution

A name such as `agent@krav` resolves through its owner root identity:

1. infer the root identity (`krav@home`)
2. load the root manifest
3. verify the manifest signature
4. find the matching service or agent entry
5. return the relevant public key and metadata

Example:

```bash
curl -s -X POST http://127.0.0.1:3000/resolve \
  -H 'content-type: application/json' \
  -d '{"name":"agent@krav"}' | jq
```

## Authorization Model

`@home` uses explicit capability permissions.

Standard permissions:

- `profile:read`
- `email:draft`
- `logs:analyze`
- `payment:send`
- `vault:delete`
- `social:post`

Verification checks:

- token issuer matches the manifest
- token signature is valid
- token is not expired
- token is not revoked
- token subject is a registered agent
- agent is active and not expired
- expected audience matches token audience when required
- requested permission is granted by the token
- requested permission is allowed by the agent
- explicit deny rules override grants
- request signature matches the agent public key
- request body hash matches the observed body
- timestamp is fresh
- nonce has not been replayed

Route-to-permission mapping:

| Request                | Required permission |
| ---------------------- | ------------------- |
| `GET /profile`         | `profile:read`      |
| `GET /public/profile`  | `profile:read`      |
| `POST /emails/draft`   | `email:draft`       |
| `POST /inbox/messages` | `email:draft`       |
| `POST /logs/analyze`   | `logs:analyze`      |
| `POST /payments/send`  | `payment:send`      |
| `DELETE /vault`        | `vault:delete`      |
| `POST /social/posts`   | `social:post`       |

Unknown routes derive a custom permission string: `custom:<method>:<path>`.

## Local Storage

By default, the local API stores demo data in `data/`:

```text
data/manifests/      Public signed manifests
data/private/        Local private key records for demo/dev
data/revocations/    Revocation indexes
data/events/         Append-only registry events
data/witness/        Witness receipts
data/replay.json     Nonce replay state
```

You can override the storage directory:

```bash
DATA_DIR=/tmp/home-data ATHOME_DEMO_PRIVATE_KEY_EXPORT=true pnpm dev
```

## Security Notes

Important boundaries:

- `ATHOME_DEMO_PRIVATE_KEY_EXPORT=true` is local demo/dev only.
- Demo private-key export is rejected when `NODE_ENV=production`.
- `POST /identities` is bootstrap-only and disabled in production.
- Mutating registry routes require a signed `X-Home-Authorization` header.
- The SDK exposes `createRootMutationSigner(...)` so local/dev clients do not have to manually build that header.
- Production deployments should not return private keys from API responses.
- Production key custody should use passkeys/WebAuthn, client-side signing, KMS, HSM, or another explicit custody boundary.
- The current revocation registry is local-first; production needs signed replication, freshness proofs, and transparency witnesses.

See:

- [Production Key Custody Plan](docs/key-custody-plan.md)
- [Distributed Revocation Model](docs/distributed-revocation-model.md)
- [Transparency and Audit Log Model](docs/transparency-and-audit-log.md)

## Development Commands

```bash
pnpm dev           # start API
pnpm demo          # run protocol demo
pnpm typecheck     # TypeScript validation
pnpm test          # Vitest suite
pnpm test:watch    # watch tests
pnpm generate:sdk  # regenerate OpenAPI schema-name pinning
```

## API Error Shape

Errors use a standard envelope:

```json
{
  "ok": false,
  "error": {
    "code": "invalid_request",
    "message": "Invalid request body",
    "details": {}
  }
}
```

Successful API responses use:

```json
{
  "ok": true
}
```

with endpoint-specific fields.

## License

TBD.
