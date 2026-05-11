# Production Key Custody Plan

The MVP keeps private keys local so the demo can run end to end. That is not a production custody model.

Production should treat private keys as sensitive custody material and keep them out of API responses, logs, and long-lived application memory.

## Key Classes

- **Root signing key**: signs the manifest and capability tokens.
- **Agent signing key**: signs requests on behalf of an authorized agent.
- **Recovery key**: restores control after loss or compromise.
- **Recovery proof material**: passkeys, verified recovery contacts, or external attestations.

## Custody Options

### WebAuthn / Passkeys

Use for human-operated root identities.

Best for:

- interactive account creation
- recovery ceremony approval
- human confirmation before key rotation or revocation

Properties:

- hardware-backed where available
- phishing-resistant
- suitable for operator approval flows

### KMS / HSM

Use for service-side signing where the server must sign on behalf of the identity.

Best for:

- hosted registry operations
- automated manifest signing
- rotation ceremonies
- controlled recovery operations

Properties:

- key material never leaves the device boundary
- signing operations are audited
- rotation and deletion are policy-controlled

### Client-side signing

Use when the user controls the private key locally.

Best for:

- personal identities
- edge-first or offline-first deployments

Properties:

- the application only handles public data and signed outputs
- export should be disabled by default

## Rotation

Recommended rotation flow:

1. generate or provision a new root key
2. mark the old key `deprecated`
3. re-sign the manifest with the new active key
4. publish a revocation or deprecation event
5. update witnesses and audit logs

Rules:

- historical signatures should remain verifiable only while the signing key is not revoked
- deprecated keys may verify historical data if the verification policy allows it
- revoked keys must fail verification

## Backup

Backups should cover:

- encrypted recovery material
- key identifiers
- revocation state
- audit-log anchors
- witness receipts

Backups must not contain raw private keys in plaintext.

Recommended backup controls:

- envelope encryption
- separate backup key
- offline storage for recovery data
- regular restore drills

## Recovery

Recovery should require at least two of:

- a recovery passkey
- a second trusted device
- a verified recovery contact
- a recovery key held in a different custody boundary
- an operator approval workflow

Recovery should not depend on an API returning private material.

## Demo / Dev Only

The current `ATHOME_DEMO_PRIVATE_KEY_EXPORT` path is only for local bootstrap and developer walkthroughs.

Production must not rely on:

- returned private keys
- exported root secret material
- unsealed plaintext backups

## Operational Guidance

- keep root keys out of application logs
- audit every rotation and recovery step
- rotate on a documented schedule
- separate approval from signing where possible
- prefer explicit custody boundaries over application memory
