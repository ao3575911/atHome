# atHome security review

Reviewed 16 October 2026 against `main`, with a live registry simulation and Fastify inject probes. This is a product security review of the trust boundaries, not a penetration test and not a claim that any advisory was exploited.

## Verdict

The cryptographic checks do what they say. The identity lifecycle around them does not. A development server will create a signed manifest and then leave that identity with no usable private key. A production server refuses to create the identity at all. Both outcomes block a safe hosted service.

## What held

These checks were executed for every person at 1, 10, 100, and 1,000 on both SQLite and the JSON store. None failed.

- An assistant token for `email:draft`, aimed at that person's inbox, verified.
- The same assistant was denied `DELETE /vault`.
- The same token was denied when the expected audience was the vault.
- Replaying the allowed request was denied.
- After `revokeCapabilityToken`, a new request with that token was denied.
- Root, agent, and service names resolved to the right kind of record.
- `POST /identities` did not put a private key in the JSON body (`privateKeyExported: false`).
- `NODE_ENV=production` returned 403 `key_custody_required` for identity creation.
- Startup still throws if `ATHOME_DEMO_PRIVATE_KEY_EXPORT=true` while `NODE_ENV=production`.
- Postgres queries in `packages/protocol/src/storage/postgres.ts` pass values as bound parameters (`$1`, `$2`). The SQLite backend uses `?` placeholders.

Ed25519 signing and verification go through Node `crypto` and canonical JSON. Mutation authorization checks issuer, method, path, body hash, and a five-minute timestamp window before it checks the signature.

## Findings

### 1. Development bootstrap strands the identity — critical

`POST /identities` generates the root key inside `LocalDevKeyCustodyProvider` and, with the API default, does not export it. The registry still writes a private record whose `privateKey` is an empty string. Reading that record later fails schema validation (`privateKey` must be at least one character). Measured on a temporary store:

| Probe                                                      | Result                                    |
| ---------------------------------------------------------- | ----------------------------------------- |
| `POST /identities`                                         | 201, `stuck@atHome`                       |
| Private key in the response                                | absent                                    |
| `privateKeyExported`                                       | false                                     |
| Stored private key length                                  | 0                                         |
| `readPrivateRecord`                                        | Zod `too_small` on `keys.root.privateKey` |
| `POST /identities/stuck@atHome/services` with no signature | 401                                       |

The only copy of the key sits in process memory. A restart drops it. The public manifest remains. Nobody can sign a mutation, including revocation.

The in-process registry used for the population run was configured with `allowPrivateKeyExport: true`, which is also the default argument on `IdentityRegistry`. That path stored a private key of length 64 in the private record. The shipping API turns export off and then writes the empty field anyway.

### 2. Production mode cannot host anyone — high

With `NODE_ENV=production`, identity creation returned 403 `key_custody_required`. `requireProductionCustody()` also rejects later mutations. That guard is the right instinct: the server must not mint keys for customers. There is no replacement path that accepts a client public key and a client signature. The production binary is safe because it is closed.

### 3. Local-dev registry persists private keys — high

When export is enabled, the private record written by `createIdentity` contains the PKCS8 material, and `LocalJsonStore` keeps those records under `data/private`. The population run confirmed `privateKeyStored: true` and `privateKeyLength: 64` on both backends. Those directories are gitignored. They are still plaintext keys on disk next to the API process.

### 4. The playground asks the Next.js server to hold the root key — high

`apps/web/lib/mutation-actions.ts` is a server action. The browser sends `privateKey` to the Next.js process, which builds `X-Home-Authorization` and calls the API. The page copy says the key stays on this machine. It does not stay in the browser. A compromised or overly logged Node process sees the root key.

`npm audit` reports Next.js 15.5.x inside an advisory range that includes denial of service and server-side request forgery in App Router server actions (GHSA-m99w-x7hq-7vfj and the related Next.js advisories returned by `npm audit`). This review did not weaponize those advisories. The playground is the feature that makes them relevant.

### 5. Fastify is inside published advisory ranges — high

The installed `fastify` is 5.8.x, and `npm audit` maps it to advisories through `<=5.12.4`, including schema validation bypass and HTTP/2 routing issues via `find-my-way`. The API is the trust boundary. Upgrade on a branch and re-run `apps/api/test` before treating the process as deployable. Vitest and tinypool critical advisories are in the test runner, not in the API runtime. They still matter on any shared CI machine that exposes the Vitest UI.

### 6. Rate limits are a single process map keyed by IP — medium

`buildRateLimiter` keeps buckets in memory. Bootstrap allows 10 requests per minute per `request.ip`. One thousand `POST /identities` calls from one inject client produced 10 responses of 201 and 990 of 429 in 197 ms. The map is not shared across instances, it is wiped on restart, and it does not evict old keys. Behind a proxy, every user can share one address and one budget of 10 joins per minute.

### 7. Witness keys do not survive the process — medium

`createMemoryWitnessService()` generates a new Ed25519 witness key in the constructor and keeps receipts in a `Map`. Revocation receipts recorded during the simulation exist only until that object is discarded. A verifier in another process cannot rely on a stable witness identity.

### 8. The passkey signer does not produce protocol signatures — medium

`PasskeyKeyCustodyProvider.sign` canonicalizes with `JSON.stringify`, asks for a WebAuthn assertion, and returns that assertion's signature bytes as base64. Manifest and token verification expect an Ed25519 signature over canonical JSON. A passkey-backed identity will not verify with the existing checker. The provider also cannot rotate a key.

### 9. Names are self-asserted — medium

`POST /identities` accepts any `id` string that parses. There is no proof that the caller controls a domain, email, or device. The first writer keeps the name. Combined with finding 1, an attacker who wins the name also creates a record that the legitimate person cannot take over, because the key was never recoverable.

## Dependency audit snapshot

`npm audit` on 16 October 2026: 3 critical, 16 high, 6 moderate, 25 total. Treat the Next.js server-action advisories and the Fastify range as the ones on the request path. Do not treat the raw count as 25 confirmed exploits.

## Not found

No string-built SQL was found in the Postgres or SQLite adapters. Mutation routes check `reply.sent` after the rate limiter, so a 429 does not fall through into the handler. Production refuses the demo export flag at startup.
