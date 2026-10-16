# atHome build and product quality

Reviewed 16 October 2026.

## Verdict

The protocol package is a credible library. The web application is a brochure wired to fixtures. The API is a careful prototype that cannot complete the journey printed on its own pricing page. Quality is highest in `packages/protocol` and lowest where the three apps meet.

## Build health

From the environment setup on this tree, immediately before this review:

| Gate                    | Result                        |
| ----------------------- | ----------------------------- |
| `npm run typecheck`     | passed                        |
| `npm run typecheck:web` | passed                        |
| `npm test`              | 86 passed, 1 skipped, 6 files |
| `npm run lint`          | Prettier clean                |
| `npm run build:web`     | 20 routes generated           |

CI on GitHub (`.github/workflows/verify.yml`) runs those gates on Node 22, plus `npm run audit:high`. That audit gate fails on today's tree: `npm audit` reports 3 critical and 16 high. The hosted Postgres job is manual and needs `ATHOME_VERIFY_DATABASE_URL`. It is not part of a normal pull request.

`node:sqlite` prints an experimental warning on Node 22.14. The SQLite path used in the simulation still completed 1,000 person lifecycles.

## What is well built

- One registry interface with JSON, SQLite, and a Postgres adapter. The population run exercised JSON and SQLite. Postgres was not started. Queries that were read use parameters.
- Mutation authorization is a real signed header, not a shared API key.
- Tests cover the unhappy paths: omitted private keys, production export refusal, audience mismatch, revocation.
- Packages are strict TypeScript ESM. The web app typechecks separately and builds.
- Production startup refuses the demo private-key export flag.

## What is rough

### The documented demo does not run

`npm run demo` exits 0 and prints nothing. `scripts/demo.ts` only calls `runDemo()` when `import.meta.main` is set. Under the current `tsx` invocation that flag is not set, so the process ends before the scenario. The simulation in this review is the run that actually exercised allow, deny, audience, replay, and revocation.

### The README describes finished work as the next step

The "next hardening lane" still lists Postgres namespace lifecycle, passkeys, and the signed playground as upcoming, and then says issues #10, #11, and #12 are closed. A new contributor cannot tell what is left. The real gap is live custody and live web data, which the v0.4 list already names and then buries under D1 and global replication.

### Two SQLite implementations

`packages/protocol/src/sqlite-store.ts` and `packages/protocol/src/storage/sqlite.ts` both talk to SQLite. The simulation used `SQLiteRegistryBackend` from `sqlite-store.ts`. Drift between them will not be caught by a single test name.

### The web app optimizes for a full screen when the API is down

Fixture fallbacks keep pages rendering. That is pleasant in a screenshot and misleading in use. The homepage can report a name available when the request never reached the registry. Pricing buttons (`Choose Personal`, `Choose Developer`, `Choose Infrastructure`) do not start checkout, a namespace claim, or an API key. Personal is listed at $0, Developer at $29, Infrastructure as custom.

### Default API storage is the JSON directory

`buildApp` uses `LocalJsonStore` unless a caller passes another backend. That store worked at 1,000 people in 36 seconds, and it also means every manifest, event, and private record is a file beside the process. SQLite was faster at the same size and keeps one file. The server does not select it.

## Product quality against the promise

The promise, from the README and the pricing page, is that a person claims a namespace, attaches agents, and delegates revocable permissions.

What a person can actually do today:

| Step                           | Library, in process | HTTP API, development                        | HTTP API, production                    |
| ------------------------------ | ------------------- | -------------------------------------------- | --------------------------------------- |
| Create a signed identity       | yes                 | yes, then the key is unreadable              | 403                                     |
| Register a service or agent    | yes                 | 401 without a key the client was never given | blocked by the production custody guard |
| Verify an allowed request      | yes                 | only if some other signer holds the key      | no                                      |
| Revoke                         | yes                 | no, same reason                              | no                                      |
| See that result in the website | n/a                 | fixture if the browser cannot reach the API  | n/a                                     |

The library is ahead of the product by the entire user journey.

## Tests versus behavior

The suite is good at locking security regressions inside `buildApp` and the registry. It did not catch the empty private-key record, because the tests that need a later mutation construct custody with `allowPrivateKeyExport: true`. The default API configuration is the one a developer hits with `npm run dev`, and it is the one that writes the empty key. A test that boots `buildApp()` with no arguments, creates an identity, restarts from the same store, and tries to read the private record would have failed today.
