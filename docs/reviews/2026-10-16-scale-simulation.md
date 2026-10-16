# Scale simulation: 1, 10, 100, and 1,000 persons

Ran 16 October 2026 on Node v22.14.0. Raw output: `docs/reviews/scale-simulation.json`.

## Scenario

Each person is one household on a single registry process:

1. Create root identity `pNNNN@atHome`.
2. Register `inbox@pNNNN` and `vault@pNNNN`.
3. Register `assistant@pNNNN` with `profile:read` and `email:draft`, denying `vault:delete` and `payment:send`.
4. Issue one token scoped to the inbox.
5. Verify an allowed inbox draft, a replay of that draft, a vault delete, an audience mismatch, and a post-revocation request.
6. Resolve the root, the agent, and the inbox.

Onboarding was sequential on one machine. This is not a multi-region test and not a Postgres test. The registry runs used in-process custody with private-key export enabled, so signing could finish. The HTTP probes used the real `buildApp()` defaults and are reported separately.

## Registry results

Every check passed for every person. Failures: 0. Events per person: 7.

| Backend | Persons | Wall clock | Per person p50 | Per person p95 |  Storage | Read all names | List all events |
| ------- | ------: | ---------: | -------------: | -------------: | -------: | -------------: | --------------: |
| SQLite  |       1 |    56.3 ms |        56.2 ms |        56.2 ms |   135 KB |         0.3 ms |          0.2 ms |
| SQLite  |      10 |   354.9 ms |        35.0 ms |        41.0 ms |   258 KB |         1.9 ms |          0.3 ms |
| SQLite  |     100 |     2.76 s |        27.5 ms |        34.7 ms |  1.59 MB |        18.3 ms |          2.7 ms |
| SQLite  |   1,000 |    24.79 s |        24.4 ms |        30.8 ms | 14.70 MB |         180 ms |         24.6 ms |
| JSON    |       1 |    38.5 ms |        38.5 ms |        38.5 ms |   8.6 KB |         0.4 ms |          0.7 ms |
| JSON    |      10 |   364.5 ms |        35.3 ms |        39.6 ms |    86 KB |         4.0 ms |          1.4 ms |
| JSON    |     100 |     3.53 s |        34.8 ms |        39.2 ms |   863 KB |        41.7 ms |         22.5 ms |
| JSON    |   1,000 |    36.29 s |        35.9 ms |        41.1 ms |  8.63 MB |         437 ms |          174 ms |

Per-person time stays flat after the first identity. SQLite at 1,000 people is about 40 onboardings per second. RSS after the 1,000-person SQLite run was 194 MB. The first SQLite identity is slower (56 ms) because the engine opens the database; the steady rate is about 24–35 ms per person.

Private keys were stored on these registry runs (`privateKeyLength` 64). That matches export-enabled custody, not the HTTP API default.

## HTTP API results

Development server, one client address, 1,000 identity creates:

| Status                | Count |                       Time |
| --------------------- | ----: | -------------------------: |
| 201 Created           |    10 |                            |
| 429 Too many requests |   990 | 197 ms for the whole burst |

The bootstrap limiter is 10 requests per minute per IP. At that setting, 1,000 people behind one address need about 100 minutes to be created, and only if nothing else uses the budget. Mutations are capped at 60 per minute and verifications at 120. A full household (two services, one agent, one token, one revoke) does not fit in the same minute as ten signups from one address.

One development identity created through `buildApp()`:

| Probe                                | Result                           |
| ------------------------------------ | -------------------------------- |
| Create `stuck@atHome`                | 201                              |
| Private key in the body              | no                               |
| On-disk private key length           | 0                                |
| Read the private record              | schema error, empty `privateKey` |
| Register a service with no signature | 401                              |

Production mode, same route: 403 `key_custody_required`.

## How to read this

The registry can hold a thousand households on a laptop. The API, as configured, can admit ten new people per minute per address, and those ten cannot attach an agent. Scaling work on replication will not change either number. The ceiling is the limiter and the missing client key, not SQLite.
