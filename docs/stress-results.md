# Stress results

Run with `npm run stress` ([scripts/stress.ts](../scripts/stress.ts)) on a clean clone, Node.js 22.21, 8 vCPU (Intel(R) Xeon(R) Processor), 26 October 2026. One process, in-memory SQLite or a temp-dir `LocalJsonStore`. Numbers are indicative, not a benchmark.

## Throughput and concurrency

| Check                                     | SQLite (in-memory) | LocalJsonStore  |
| ----------------------------------------- | ------------------ | --------------- |
| Sign requests, sequential                 | 4,000/s            | 1,670/s         |
| Verify requests, sequential               | 1,640/s            | 300/s           |
| 500 parallel verifications                | 500 ok in 345 ms   | 500 ok in 1.3 s |
| One request verified 50 times in parallel | 1 accepted         | 1 accepted      |

Before [#68](https://github.com/ao3575911/atHome/pull/68) the last two rows failed: SQLite accepted the same request 50 times, and `LocalJsonStore` threw `ENOENT` on 439 of 500 parallel verifications ([#62](https://github.com/ao3575911/atHome/issues/62), [#63](https://github.com/ao3575911/atHome/issues/63)). Replay protection across several API instances is tracked in [#67](https://github.com/ao3575911/atHome/issues/67).

## Failure cases

All rejected with a typed outcome: tampered body (`body_hash_mismatch`), tampered signature (`invalid_request_signature`), replay (`nonce_replayed`), denied permission (`permission_denied`), revoked token (`token_revoked`), expired token (`token_expired`, reported in `reason` rather than `code`: [#66](https://github.com/ao3575911/atHome/issues/66)). An unknown identity throws instead of returning an outcome ([#65](https://github.com/ao3575911/atHome/issues/65)).

## Large inputs

| Input                                      | Result                                                                |
| ------------------------------------------ | --------------------------------------------------------------------- |
| 1 MB / 10 MB / 50 MB body, sign and verify | ok in 13 ms / 118 ms / 640 ms                                         |
| Object with 200,000 keys, hash             | ok in 150 ms                                                          |
| JSON nested 1,000 deep                     | ok                                                                    |
| JSON nested 5,000 or 20,000 deep           | stack overflow ([#64](https://github.com/ao3575911/atHome/issues/64)) |
