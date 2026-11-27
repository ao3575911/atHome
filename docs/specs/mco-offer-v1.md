# Mesh capability offers (mco-offer/v1)

An MCO offer is a signed catalog of the calls one registered service accepts, and of the other services those calls may delegate to. Agents stop guessing the permission string and the next hop. The mesh denies a call that is not on the offer.

Existing identity manifests, capability tokens, signed requests, and `X-Home-Authorization` payloads are unchanged. This document adds a claim type, two event types, and four routes.

## Offer

```json
{
  "version": "mco-offer/v1",
  "id": "inbox#2026-11-28T00:00:00.000Z",
  "issuer": "krav@atHome",
  "serviceId": "inbox",
  "calls": [
    {
      "id": "draft-message",
      "method": "POST",
      "path": "/inbox/messages",
      "permission": "email:draft",
      "delegatesTo": ["pay"]
    }
  ],
  "issuedAt": "2026-11-28T00:00:00.000Z",
  "expiresAt": "2026-11-28T01:00:00.000Z",
  "signatureKeyId": "root",
  "signature": "<ed25519 signature over the offer without this field>"
}
```

Rules:

- `serviceId` is a service already on the manifest. Ids match `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`.
- Calls are stored sorted by `id`. Call ids are unique. The same method, path, and permission appear on at most one call. `delegatesTo` is sorted, unique, and cannot name the offer's own service.
- Authorization matches method, path, and permission together, then checks `delegatesTo` on that call. Two calls may share a route when their permissions differ. A requested hop is allowed when any matching call lists it.
- A delegate must be another registered service on the same identity.
- The delegation graph across offers on one identity is acyclic.
- The offer is signed by a root key on the manifest. A deprecated root key still verifies, so root rotation does not drop the offer. A revoked root key does not.
- `ttlSeconds` on publish defaults to 30 days and must be from 60 to 31536000.

The signed offer is stored as a manifest claim:

| Field   | Value                              |
| ------- | ---------------------------------- |
| `id`    | `<serviceId>#mco`                  |
| `type`  | `mco.offer`                        |
| `value` | canonical JSON of the signed offer |

Publishing again for the same service replaces that claim. The event log records `mco.published` or `mco.retired` with `offerId`, `serviceId`, and `callCount` where those fields apply. The event does not carry the private key or the full offer.

## Routes

| Method | Path                                    | Auth                   | Result                       |
| ------ | --------------------------------------- | ---------------------- | ---------------------------- |
| `GET`  | `/identities/:id/mco`                   | No                     | Current offers and edges     |
| `POST` | `/identities/:id/mco`                   | `X-Home-Authorization` | Re-signed manifest and offer |
| `POST` | `/identities/:id/mco/authorize`         | No                     | `{ ok, verification }`       |
| `POST` | `/identities/:id/mco/:serviceId/retire` | `X-Home-Authorization` | Manifest without that claim  |

`authorize` checks the catalog. It does not consume a nonce and it does not replace `POST /verify/request`. A denial is `verification.ok: false` with one of:

- `mco_offer_invalid`
- `mco_offer_not_active`
- `mco_offer_expired`
- `mco_call_not_offered`
- `mco_permission_mismatch`
- `mco_delegation_not_offered`

Worked denial: actor `trust me bro` asks `pay` for `POST /payments/send` and a delegation to `vault`. The pay offer lists no such edge, so the code is `mco_delegation_not_offered`.

A tampered claim fails closed. If the manifest is re-signed around an offer whose own signature no longer matches, `readMcoMesh` rejects the identity's mesh instead of returning the altered call.
