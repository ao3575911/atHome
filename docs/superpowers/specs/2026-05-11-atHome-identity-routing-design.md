# Home Identity Routing Protocol Design

## Goal

Build a first working version of a universal personal identity and agent routing protocol centered on signed root identities like `krav@atHome`, resolvable sub-identities like `agent@krav`, and verifiable capability-based authorization for human and AI agent requests.

## Architecture

The MVP is a TypeScript monorepo with three runtime surfaces: a protocol package, an HTTP API, and a thin SDK. The protocol package owns canonical JSON signing, Ed25519 key generation, identity manifest validation, service and agent registration rules, capability token issuance, request verification, and local JSON storage.

The API is a Fastify server that wraps the protocol package and persists manifests and private keys locally for development. The SDK is a small fetch-based client for resolving identities and checking tokens and signed requests against a running API.

## Storage Model

Use local JSON files under `data/` as the durable store. Public manifests live in `data/manifests/`, private local key material lives in `data/private/`, and replay-nonce state lives in `data/replay.json`. This keeps the MVP inspectable without adding a database migration layer.

## Signing Model

Use Node.js Ed25519 signing through `node:crypto`. Manifest, capability-token, and signed-request payloads are serialized with deterministic key ordering before signing. The signature field is excluded from the signed payload and re-attached after signing.

## Resolution Model

Names resolve by root identity. A name like `agent@krav` resolves against the root manifest `krav@atHome`, then the resolver looks for a service or agent entry matching the requested name and returns the relevant public key plus manifest signature verification status.

## Verification Model

Verification is layered. Manifest signature verification proves the public manifest was authored by the root key. Capability verification proves the root authorized a specific agent and permission set. Request verification proves the specific agent signed the request, the nonce was not replayed, the timestamp is fresh, and the requested permission is allowed.

## MVP Scope

This version covers root registration, service registration, agent registration, capability issuance, resolution, capability verification, request verification, a demo script, and unit tests. It does not attempt decentralized storage, distributed revocation, or wallet/passkey integrations yet.
