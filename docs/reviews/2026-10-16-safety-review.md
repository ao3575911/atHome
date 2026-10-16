# atHome safety review

Reviewed 16 October 2026. Safety here means whether a person can delegate an agent, bound what it may do, and take that power back, without the software inventing extra authority or hiding a failure.

## Verdict

The policy engine is the safe part. The product wrapped around it can squat a name, lose the only key, and show a fixture when the real answer was a failure. High-impact permissions such as `payment:send` and `vault:delete` are ordinary strings. Nothing in the protocol asks a person to confirm them or caps how far they go.

## Delegation behavior that held

Each simulated person received one assistant. The assistant's allowed set was `profile:read` and `email:draft`. The denied set included `vault:delete` and `payment:send`. The token audience was that person's inbox.

Across 1, 10, 100, and 1,000 persons, on SQLite and on JSON:

| Check                                | Expected     | Result       |
| ------------------------------------ | ------------ | ------------ |
| Draft an inbox message               | allow        | 100% allowed |
| Delete the vault                     | deny         | 100% denied  |
| Present the inbox token to the vault | deny         | 100% denied  |
| Replay the allowed request           | deny         | 100% denied  |
| Use the token after revocation       | deny         | 100% denied  |
| Resolve root, agent, and inbox       | correct type | 100% correct |

That is the safety property worth keeping. An agent does not inherit the owner's full authority. Audience and revocation are enforced in the verifier, not in a comment.

## Where a person can still be harmed

### Lost control of a name

The HTTP development path creates `stuck@atHome` and returns no key. The on-disk private record cannot be read back. After a restart, the name exists and no one can rotate, revoke, or correct it. A safety system that cannot revoke is not safe. It is a signed artifact with no owner.

Production avoids this by returning 403. The person is safe from a bad signup because signup does not exist.

### Fixture results look like answers

The namespace widget and several ops panels catch a failed fetch and render fixture data. During environment setup, a search for an identity that existed on the API showed "available" and "fixture fallback" with "Failed to fetch", because the browser could not call port 3000. The status page, rendered on the server, correctly reported the API reachable. A person looking at the homepage can be told a taken name is free. An operator looking at ops can be shown a fixture audit row. The panels sometimes label the source. The homepage badge still reads as an availability answer.

### High-impact permissions have no second step

`payment:send`, `vault:delete`, and `social:post` are in `STANDARD_PERMISSIONS`. Verification checks that the token lists the string, the agent allows it, and the audience matches. There is no amount, no recipient allowlist, no expiry shorter than the caller's `ttlSeconds`, and no required human approval. A correctly signed token for `payment:send` is enough. The simulation denied vault deletion only because the assistant was configured without that permission. A person who issues the wider token gets the wider agent.

### Revocation depends on keys the product just threw away

Token revocation worked inside the process that still held the key. The HTTP client cannot produce `X-Home-Authorization`, so the same client cannot revoke. Witness receipts are signed by an in-memory witness key. Another machine cannot tell a receipt from this process apart from one signed by a witness that no longer exists.

### Abuse control is a per-address counter

One thousand join attempts from one address created 10 identities and rejected 990. That slows a single noisy client for one minute. It does not slow ten machines, and it resets when the process restarts. Names are not tied to a verified person. The first caller to claim a name keeps it, including names that look like someone else.

### The ops console can invite action on invented data

Ops copy says controls are mocked. Health probes are live when the API answers. Audit and abuse views still fall back to fixtures. A safety or trust operator who treats that screen as the registry will act on rows the protocol never wrote.

## Safety bar for the next milestone

A build is safe enough to put in front of another person when all of the following are true:

1. The person generates or holds the root key, and the server stores only the public key.
2. Creating an identity, registering one agent, allowing one request, and revoking it can be done after a process restart.
3. A failed lookup renders an error, never a plausible "available".
4. `payment:send`, `vault:delete`, and `social:post` cannot be issued unless the token carries a bound (amount, target, or an explicit confirmation id) that the verifier checks.
5. The witness public key is stable and published with the receipt.

The 1,000-person run shows the policy checks can meet that bar. The HTTP product does not meet it yet.
