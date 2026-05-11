# Revocation Transparency and Audit Log Model

Revocation is only useful if verifiers can observe it consistently. The production design should therefore expose revocation state through a transparent, append-only audit layer.

## Requirements

- revocation events must be signed by the identity owner or an authorized delegate
- revocation events must be immutable once published
- verifiers must be able to prove the presence of a revocation event
- logs should be indexable by identity, subject id, key id, and token id
- audit consumers should be able to inspect who changed what and when

## Event Types

Recommended event types:

- `identity.created`
- `key.added`
- `key.deprecated`
- `key.revoked`
- `service.added`
- `agent.added`
- `agent.revoked`
- `token.issued`
- `token.revoked`
- `request.verified`
- `request.denied`

## Audit Record Shape

Each record should include:

- event id
- identity id
- subject id
- event type
- timestamp
- actor key id
- payload hash
- previous event hash
- signature
- optional witness receipt

The payload should exclude any raw private material or secrets.

## Transparency Properties

### Append-only

New records can be added, but existing records should never be edited in place.

### Hash chained

Each record should reference the previous digest so tampering is detectable.

### Witnessed

Important revocation events should be anchored to a public witness or transparency log.

### Queryable

Consumers should be able to ask:

- is this agent revoked?
- is this capability token revoked?
- is this key revoked?
- when did the revocation happen?
- what key signed the latest manifest?

## Retention

Retention should be long enough to support:

- incident response
- forensic review
- customer support
- replay and dispute analysis

At minimum, revocation and key-rotation events should outlive the tokens and signatures they invalidate.

## Privacy

Audit logs should be minimized:

- store hashes rather than raw sensitive request bodies when possible
- redact secrets
- avoid logging private keys
- avoid logging bearer tokens in plaintext

## Relation to the Current MVP

The current repository already stores local revocations and replay state. That is useful as a single-node bootstrap, but it is not a transparent audit system.

The production model should turn those local records into signed, replicated, append-only audit events.
