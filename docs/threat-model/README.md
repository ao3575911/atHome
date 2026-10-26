# A1 identity and trust threat model

## Assets and trust boundaries

| Asset                | Boundary                    | Required control                                                                    |
| -------------------- | --------------------------- | ----------------------------------------------------------------------------------- |
| Private signing key  | Custody provider or caller  | Never serialize it in A1 documents, CLI output, or registry records                 |
| A1 identity document | Untrusted transport/storage | Verify the envelope against a bound trusted key                                     |
| Creator proof        | Untrusted transport/storage | Validate schema, issuer/key anchor, timestamps, signature, and revocation           |
| Registry response    | Remote service              | Treat as optional, stale/unavailable/untrusted until local verification succeeds    |
| Capability request   | atHome protocol             | Preserve existing signature, capability, explicit-deny, timestamp, and nonce checks |

## Threats and mitigations

| Threat                          | A1 behavior                                                                      | Residual risk                                           |
| ------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Forged creator proof            | Ed25519 verification against locally configured issuer/key anchors               | Compromised trusted issuer key                          |
| Modified proof claim or subject | Canonical signed payload verification fails                                      | None after correct key binding                          |
| Expired or future proof replay  | Expiry is required by default; future issuance is bounded by clock skew          | Verifier clock accuracy                                 |
| Revoked proof or key            | Caller-supplied revocation state fails verification                              | Revocation distribution latency                         |
| Registry outage or tampering    | Typed failure; no online lookup is needed for local verification                 | Users may need an offline trust anchor                  |
| Stale registry record           | 24-hour default freshness bound; caller can choose a stricter bound              | `updatedAt` is not signed                               |
| Unsafe private-key onboarding   | CLI accepts public keys only; production custody stays external                  | Callers must still protect their custody provider       |
| Policy bypass                   | Creator-proof policy is opt-in but runs only after existing authorization checks | Routes must deliberately opt in where proof is required |

## Security invariants

1. A signature envelope identifies a key; it does not make the key trusted.
2. A registry result is data, never an authorization decision.
3. No A1 component weakens atHome's explicit deny precedence.
4. No A1 component changes legacy signed payload bytes.
5. Failure to parse, fetch, validate, or verify fails closed for the A1
   operation.

## Out of scope

A1 does not provide key recovery, global nonce coordination, a registry
service, transparency guarantees, anonymous credential proofs, or a DID
method. Those require separate designs and threat models.
