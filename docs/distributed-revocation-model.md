# Distributed Revocation and Registry Model

This repository currently uses a local JSON store for the MVP. That is enough for a single-node demo, but it is not the production registry model.

The production shape should be a signed, replicated revocation registry with an append-only event log and deterministic read models.

## Goals

- preserve a single owner of the root identity
- make revocation visible across replicas
- avoid trusting a mutable local file as the source of truth
- allow offline verification of signed manifests, tokens, and requests
- support anti-entropy synchronization between independent nodes

## Proposed Layers

### 1. Local authority

The root identity remains the authority that signs:

- identity manifests
- capability tokens
- key rotation events
- revocation events

This repository can keep local-first creation flows, but production writes should emit signed events rather than mutate a file directly.

### 2. Append-only event log

Each identity gets an event stream with immutable entries such as:

- `identity.created`
- `key.added`
- `key.deprecated`
- `key.revoked`
- `service.added`
- `agent.added`
- `agent.revoked`
- `token.issued`
- `token.revoked`

Each event should include:

- event id
- identity id
- event type
- timestamp
- sequence number
- previous event hash
- payload hash
- signer key id
- signature

The hash chain lets replicas prove that an event was inserted into a consistent history.

### 3. Registry replicas

Replicas should materialize read models from the signed event log:

- public manifest view
- revocation index
- replay-nonce state
- audit-log feed

Replicas may be:

- a hosted registry service
- a self-hosted registry mirror
- a local edge cache

Replication should be eventually consistent, but verification should fail closed when a verifier cannot prove freshness for a required revocation class.

### 4. Witness / transparency layer

Critical revocation events should be published to one or more public witnesses.

Witnesses do not need private keys. They only need to:

- store event digests
- timestamp receipts
- expose inclusion proofs
- detect equivocation between replicas

This is the point where a transparency log becomes useful: a verifier can prove that a key or token was revoked even if the original registry replica is unavailable.

## Trust Model

- the identity owner signs authority-bearing events
- replicas verify event signatures before indexing
- verifiers check the manifest signature and the revocation index
- audit consumers read the append-only log, not a mutable point-in-time file

## Conflict Rules

- `revoked` beats `deprecated`
- `revoked` beats `active`
- a token or key revoked by any trusted replica must be treated as revoked for verification
- if replicas disagree on freshness, verifiers should prefer the newest witness-backed event they can prove

## Practical API Shape

The current code can evolve toward interfaces like:

- `appendEvent(identityId, event)`
- `syncEvents(identityId, fromSequence)`
- `getRevocationStatus(identityId, subjectId)`
- `getManifestView(identityId)`
- `getAuditLog(identityId, since)`

## Non-goals for MVP

- decentralized consensus
- live global quorum writes
- mutable client-side trust in a single JSON file

The MVP stays local-first. The production registry becomes an append-only, signed, replicated system.
