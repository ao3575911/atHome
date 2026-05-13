# Home Registry Hardening Design

## Goal

Turn the current local-first `atHome` developer product into a clearer v0.3-ready foundation with:

- a real registry backend abstraction built around append-only revocation events
- a witness/transparency service for revocation proofs
- explicit production key-custody boundaries instead of demo key export
- stable OpenAPI component names for SDK generation

The goal is not to add a distributed consensus system yet. The goal is to make the trust seams explicit and replace the current local JSON-only assumptions with portable interfaces.

## Scope

This pass covers four related subsystems:

1. registry storage and eventing
2. revocation transparency and audit proofs
3. production key custody
4. OpenAPI normalization for SDKs

These pieces are coupled because they all sit on the protocol boundary. They should be designed together, but implemented behind small interfaces.

## Approaches

### Option A: Local-first interfaces with production-shaped adapters

Keep the current JSON store as the default backend, but add interfaces for:

- append-only registry events
- witness proof emission
- key custody providers
- OpenAPI spec post-processing

This is the recommended path.

Tradeoff: it does not immediately provide external durability, but it keeps the codebase small and testable while creating the right seams for a later backend.

### Option B: Direct cloud provider integration

Wire the registry to a specific hosted datastore and KMS/HSM provider now.

Tradeoff: more operational realism, but it couples the repo to a provider and makes local demo flows and tests harder to keep simple.

### Option C: Full distributed log protocol now

Implement replicated event streams, witness quorum logic, and cross-node sync in one pass.

Tradeoff: highest completeness, but too large for a clean v0.3 hardening iteration and too risky to keep aligned with the current codebase.

## Architecture

The implementation should split into four focused layers.

### 1. Registry backend

Introduce a backend interface in `packages/protocol` that owns identity state and append-only events.

Responsibilities:

- store identity manifests
- append signed registry events
- read materialized views for manifests, revocations, and replay state
- support key rotation and revocation as events rather than ad hoc file mutation

The current local JSON store becomes one adapter, not the architecture.

### 2. Witness service

Introduce a witness service that records revocation proofs.

Responsibilities:

- receive signed revocation event payloads
- return a receipt with digest, timestamp, and witness signature
- expose proofs that a key/token/agent revocation was observed
- let verifiers check revocation without trusting only the backend’s mutable state

This service can be local-only in the repo, but the interface should match a future remote witness.

### 3. Key custody provider

Replace the demo private-key export path with a custody abstraction.

Responsibilities:

- create and store root keys
- sign manifests, capability tokens, and request materials
- support local dev custody without exposing raw secret export by default
- allow future adapters for WebAuthn, KMS, and HSM

The code should make it impossible to treat demo key export as a production feature.

### 4. OpenAPI post-processor

Keep Fastify-generated route discovery, but normalize the resulting OpenAPI document before serving it.

Responsibilities:

- stabilize component names
- preserve route accuracy
- map generated anonymous schema ids into named SDK-facing components
- keep `/openapi.json` useful for code generation and downstream docs

## Data Flow

### Identity and registry writes

1. the registry backend appends a signed event
2. the backend updates its materialized manifest and revocation views
3. the witness service records a digest receipt for revocation-sensitive events
4. the API exposes the updated public manifest and proof metadata

### Verification

1. a verifier loads the manifest and revocation state
2. the verifier checks the manifest signature
3. the verifier checks witness-backed revocation proofs for relevant subjects
4. the verifier evaluates authorization and request signatures using the current policy code

### OpenAPI generation

1. Fastify builds the route graph from route schemas
2. `app.swagger()` returns the generated document
3. a post-processor renames or anchors unstable component ids
4. `/openapi.json` serves the normalized result

## Error Handling

Failures should remain explicit and structured.

Expected classes:

- missing identity / manifest
- invalid manifest signature
- revoked key / token / agent
- custody provider unavailable
- witness proof missing or stale
- OpenAPI normalization failure

The API should fail closed when a required proof or custody boundary is unavailable.

## Implementation Boundaries

The following boundaries should remain clean:

- `packages/protocol` owns protocol types, signing, verification, and backend interfaces
- `apps/api` owns HTTP exposure and route wiring
- a new witness module owns proof receipt formatting
- a new custody module owns secret handling and signing delegation
- OpenAPI normalization should be a small pure function, not an API behavior change

## Testing Strategy

Add tests in layers:

- backend event append and replay
- revocation receipt generation and verification
- custody guardrails for demo vs production
- OpenAPI component stabilization
- authorization and verification negative cases remain in protocol tests

Tests should prove:

- append-only event sequencing works
- revocation proofs are attached and verifiable
- production cannot accidentally enable raw key export
- the normalized OpenAPI spec contains stable component names

## Non-Goals

- distributed consensus
- multi-region quorum writes
- a complete production KMS/WebAuthn integration
- a public transparency network

Those are future integration steps after the backend abstraction is in place.

## Success Criteria

This pass is successful if:

- the registry no longer depends on only direct JSON mutation
- revocation events have an auditable proof path
- production custody cannot leak private keys by configuration accident
- the OpenAPI document is stable enough for SDK generation
- the current demo and tests still work
