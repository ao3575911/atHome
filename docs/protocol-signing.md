# Protocol Signing

This document describes the current signing boundary used by the `atHome` developer product.

The implementation uses real Ed25519 signatures from Node.js `node:crypto`. Payloads are serialized with the repository's canonical JSON helper before signing or verification.

## Canonical JSON

Canonicalization is deterministic:

- object keys are sorted recursively
- `undefined` values are omitted
- arrays preserve order
- dates are not special-cased beyond normal JSON stringification

The signed message is the UTF-8 byte sequence of the canonical JSON string returned by the helper.

In pseudocode:

```ts
const message = Buffer.from(canonicalize(payload));
const signature = ed25519.sign(message, privateKey);
```

Verification uses the same canonicalization step before calling Ed25519 verify.

## Signed Manifest Bytes

The manifest signature covers the manifest draft object without the `signature` field.

Signed fields:

- `id`
- `version`
- `publicKeys`
- `services`
- `agents`
- `claims`
- optional `recovery`
- `updatedAt`
- optional `expiresAt`

Excluded field:

- `signature`

The public manifest is therefore a signed statement of the current identity state and its trusted keys.

## Signed Capability Token Bytes

The capability token signature covers the token draft object without the `signature` field.

Signed fields:

- `issuer`
- `subject`
- optional `audience`
- `permissions`
- optional `denied`
- `issuedAt`
- `expiresAt`
- optional `nonce`

Excluded field:

- `signature`

Before signing, permissions and denied permissions are normalized and sorted so the same logical token always produces the same signed bytes.

## Signed Request Bytes

The signed request signature covers the request draft object without the `signature` field.

Signed fields:

- `actor`
- `issuer`
- `capabilityToken` including the nested token signature
- `method`
- `path`
- `bodyHash`
- `timestamp`
- `nonce`

Excluded field:

- `signature`

The request signature therefore commits to the exact capability token that was presented at verification time, not just to the token's issuer or subject.

## Body Hashing

`bodyHash` is the SHA-256 hex digest of:

- the canonical JSON string for structured bodies
- the raw string value for string bodies
- the raw bytes for `Buffer` bodies
- the empty string when no body is supplied

This keeps the signed request stable while allowing the verifier to re-hash the observed body and compare it to the committed hash.

## Known Limitations

This is a developer product, not a finished trust platform.

- the docs/demo slice is local-first
- private key export exists for local bootstrap flows only
- revocation and audience policy should move into first-class protocol data before production use
- replay protection is local and nonce-scoped
- distributed storage, transparency logs, and remote key custody are future work

## Why Canonical JSON

Canonical JSON keeps signing stable across different runtimes and object key insertion orders. Without canonicalization, logically identical payloads could serialize differently and produce different signatures.

For this product, that matters because the signed objects are meant to move through APIs, SDKs, and example scripts without changing meaning.
