# A1 identity and trust consolidation migration

## Goal and boundaries

A1 creates stable boundaries for adjacent identity concepts without importing
or vendoring donor repositories. It preserves atHome's local-first behavior:
existing manifests, capability tokens, signed requests, mutation
authorizations, and route-permission behavior continue unchanged.

```text
identity-core ──> creator-proof ──> registry-client
       │                 │                 │
       └─────────────────┴──────────────> CLI / opt-in policy hook
```

| Package                   | Responsibility                                                | Not responsible for                    |
| ------------------------- | ------------------------------------------------------------- | -------------------------------------- |
| `@athome/identity-core`   | A1 identity keys, canonical bytes, Ed25519 signing interfaces | Key storage or production key export   |
| `@athome/creator-proof`   | Local proof validation, trust-anchor and revocation checks    | Publishing or resolving proofs         |
| `@athome/registry-client` | Typed remote lookup and explicit failure states               | Making a registry available or trusted |
| `@athome/cli`             | Public-key onboarding and proof/registry verification         | Generating or persisting private keys  |

The `schemas/` directory contains provisional JSON Schema 2020-12 contracts.
They are not replacements for `IdentityManifest` or `CapabilityToken`.

## Integration sequence

1. Adopt the A1 JSON schema only for new A1 documents.
2. Use `@athome/identity-core` to sign or verify a new A1 artifact.
3. Bind creator-proof issuers to locally configured trust anchors.
4. Optionally resolve a proof with `@athome/registry-client`; verify the
   returned proof locally before use.
5. Add `createCreatorProofPolicy()` to a request only where a route requires
   creator proof. Existing `canPerform()` grants and explicit deny precedence
   run first and are unchanged.

The migration has no automatic manifest conversion and no data migration. A
consumer that wants an A1 identity document should create and sign it beside
the existing manifest, then publish the new artifact only after both forms
verify.

## Compatibility guarantees

- Existing public APIs and protocol signatures are unchanged.
- atHome's existing `spki-der-base64` Ed25519 key representation is the A1
  default.
- Offline capability and request verification does not call a registry.
- A registry outage, malformed response, stale record, or untrusted proof is
  a typed failure; it is never treated as proof success.
- A1 proof policy is opt-in. Absent hooks retain existing authorization
  outcomes and denial precedence.

## CLI onboarding

Run the workspace CLI with:

```bash
npm run start -w @athome/cli -- identity init alice@atHome \
  --public-key <spki-der-base64> --output alice.identity.json
```

The command writes only a public identity document. It never accepts a
private-key flag, generates a private key, or writes key material. Use a
custody provider or external signer for production signing.

## Registry behavior

The provisional registry endpoint is:

```text
GET /v1/creator-proofs/{url-encoded-subject}
```

It returns `{ "proof": <creator-proof>, "updatedAt": <ISO timestamp> }`.
The client has no persistent cache; it treats records older than 24 hours as
stale by default. `updatedAt` is freshness metadata, not a cryptographic
assertion. The returned proof remains untrusted until local trust-anchor and
signature verification succeeds.

## Donor boundaries

vouch-id informs the offline attestation and independently configured issuer
trust model. dark-swan informs portable proof documents and optional
human-facing pseudonyms. Neither project's wire format, deterministic seed
mode, local registry implementation, or CLI code is imported into atHome.

## Follow-up decisions

- Add cross-runtime golden vectors before browser signer support claims A1
  interoperability.
- Decide whether an A1 document needs a standard DID method; A1 IDs are
  currently opaque.
- Define durable nonce storage only for flows that need replay prevention.
- Define registry publication and transparency-log semantics separately from
  local proof verification.
