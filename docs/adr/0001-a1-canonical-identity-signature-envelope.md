# ADR 0001: A1 canonical identity and signature envelope

- Status: Accepted
- Date: 2026-10-26

## Context

atHome already signs manifests, capability tokens, requests, and mutation
authorizations with Ed25519 over recursively key-sorted JSON. vouch-id adds
offline attestations, while dark-swan adds portable proof cards and rotating
human-facing handles. Their concepts are useful, but their public-key
serializations and wire formats are not interchangeable with atHome's
established formats.

Changing an existing signed field changes the bytes covered by its signature.
Therefore A1 defines an additive envelope and leaves current atHome wire
formats unchanged.

## Decision

### Versioned identity document

The A1 identity document has `version: "a1"`, an opaque `id`, one or more
public keys, and ISO-8601 `createdAt` and `updatedAt` timestamps. A document
signature is optional because identity documents may be assembled before a
custody provider signs them. A signed document uses the same signature
envelope described below.

`@athome/identity-core` accepts these public-key encodings:

| Encoding          | Use                                                                  |
| ----------------- | -------------------------------------------------------------------- |
| `spki-der-base64` | Default. This is atHome's existing public-key representation.        |
| `raw-base64url`   | Explicit interoperation adapter for raw 32-byte Ed25519 public keys. |

`Ed25519` is the only A1 signature algorithm. Private-key input to the local
signer is PKCS#8 DER base64, matching atHome's current implementation. The
core package does not persist keys, and production callers should provide a
custody-backed signer rather than exporting a private key.

### Signature envelope

```json
{
  "version": "a1",
  "algorithm": "Ed25519",
  "keyId": "root",
  "signature": "<standard-base64-ed25519-signature>"
}
```

The envelope identifies a key but is not a trust anchor. A verifier must bind
the issuer and `keyId` to a trusted public key before accepting a signature.
The signature is standard padded-or-unpadded base64 as accepted by Node's
decoder; producers use standard base64.

### Canonical bytes

The signed bytes are UTF-8 bytes of JSON after recursively:

1. sorting object keys lexicographically,
2. omitting properties whose value is `undefined`,
3. preserving array order, and
4. emitting JSON without insignificant whitespace.

Dates are strings, never JavaScript `Date` objects. Unknown data structures,
circular values, and non-JSON values are not valid signed payloads.

### Time, nonce, status, and revocation

An attestation carries `issuedAt`, optional `expiresAt`, and optional `nonce`
in the signed payload. Creator-proof verification requires `expiresAt` by
default, rejects expired proofs, and allows at most five minutes of future
clock skew. A nonce is only replay-safe when the caller stores and checks it;
A1 does not claim distributed nonce coordination.

Key and proof revocation are verifier inputs. A revoked A1 key fails
verification. Creator-proof verification accepts an explicit revoked-proof
set. Registry responses are not revocation authority and do not bypass either
check.

### Pseudonyms

`PseudonymRotationAdapter` is an extension interface only. A1 does not define
a pseudonym derivation, issue a daily handle, or treat a display label as a
stable identity identifier.

## Compatibility

No `IdentityManifest`, `CapabilityToken`, `SignedRequest`, or mutation
authorization field changes in this decision. Existing atHome manifests use
the `spki-der-base64` representation and continue to be verified by
`@athome/protocol`. A future adapter may construct an A1 document from a
manifest, but it must be a new signed artifact rather than a reinterpretation
of legacy signature bytes.

## Consequences

- Offline verification remains possible when a verifier already has a trusted
  key.
- Remote registry lookup remains optional and cannot establish trust on its
  own.
- Consumers can opt into raw-key compatibility deliberately instead of
  accepting ambiguous key strings.
- Browser and external signer integrations must produce these canonical bytes
  before they can claim A1 interoperability.
