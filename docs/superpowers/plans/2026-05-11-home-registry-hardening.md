# Home Registry Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the local-first @home MVP into a cleaner v0.3-ready foundation with a real registry backend abstraction, revocation transparency proofs, production key-custody boundaries, and stable OpenAPI output for SDK generation.

**Architecture:** Keep the current protocol package as the source of truth, but split it into explicit backend, witness, and custody seams. The local JSON store remains the default adapter for development, while the API only talks to abstractions that can later point at an external registry, witness service, or KMS/WebAuthn provider. The OpenAPI document stays Fastify-generated, then gets normalized into stable component names before being served.

**Tech Stack:** TypeScript, Node.js `node:crypto` Ed25519, Fastify, Zod, Vitest, pnpm workspaces.

---

### Task 1: Introduce append-only registry events and a backend abstraction

**Files:**

- Create: `packages/protocol/src/events.ts`
- Create: `packages/protocol/src/backend.ts`
- Modify: `packages/protocol/src/types.ts`
- Modify: `packages/protocol/src/schemas.ts`
- Modify: `packages/protocol/src/store.ts`
- Modify: `packages/protocol/src/registry.ts`
- Test: `packages/protocol/test/backend.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from "vitest";
import { createMemoryRegistryBackend } from "@home/protocol";

describe("registry backend events", () => {
  it("appends revocation events and materializes revoked state", async () => {
    const backend = createMemoryRegistryBackend();

    await backend.appendEvent("krav@home", {
      id: "evt_1",
      type: "token.revoked",
      subjectId: "token-123",
      timestamp: "2026-05-11T00:00:00.000Z",
      signerKeyId: "root",
      payloadHash: "abc123",
      previousHash: "genesis",
      signature: "sig",
    });

    const revocation = await backend.getRevocationState("krav@home");
    expect(revocation.revokedCapabilityTokens["token-123"]).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test packages/protocol/test/backend.test.ts`
Expected: module resolution or missing export failure before the backend abstraction exists.

- [ ] **Step 3: Write minimal implementation**

Add a small event model:

```ts
export type RegistryEventType =
  | "identity.created"
  | "key.added"
  | "key.deprecated"
  | "key.revoked"
  | "service.added"
  | "agent.added"
  | "agent.revoked"
  | "token.issued"
  | "token.revoked";
```

Add a backend interface:

```ts
export interface RegistryBackend {
  appendEvent(identityId: string, event: RegistryEvent): Promise<void>;
  listEvents(identityId: string): Promise<RegistryEvent[]>;
  getManifest(identityId: string): Promise<IdentityManifest | null>;
  getRevocationState(identityId: string): Promise<RevocationRecord | null>;
}
```

Keep `LocalJsonStore` as the default adapter, but move revocation writes to event appends plus a materialized view update.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test packages/protocol/test/backend.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/events.ts packages/protocol/src/backend.ts packages/protocol/src/types.ts packages/protocol/src/schemas.ts packages/protocol/src/store.ts packages/protocol/src/registry.ts packages/protocol/test/backend.test.ts
git commit -m "introduce append-only registry backend events"
```

### Task 2: Add a witness service for revocation proofs

**Files:**

- Create: `packages/protocol/src/witness.ts`
- Modify: `packages/protocol/src/types.ts`
- Modify: `packages/protocol/src/registry.ts`
- Modify: `apps/api/src/app.ts`
- Test: `packages/protocol/test/witness.test.ts`
- Test: `apps/api/test/hardening.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from "vitest";
import { createLocalWitnessService } from "@home/protocol";

describe("witness service", () => {
  it("returns a signed receipt for a revocation proof", async () => {
    const witness = createLocalWitnessService();
    const receipt = await witness.recordRevocation({
      identityId: "krav@home",
      kind: "token",
      subjectId: "token-123",
      revokedAt: "2026-05-11T00:00:00.000Z",
      payloadHash: "abc123",
    });

    expect(receipt.receiptId).toBeTypeOf("string");
    expect(receipt.signature).toBeTypeOf("string");
    expect(await witness.verifyReceipt(receipt)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test packages/protocol/test/witness.test.ts`
Expected: missing export / missing module failure.

- [ ] **Step 3: Write minimal implementation**

Define a witness receipt:

```ts
export interface RevocationReceipt {
  receiptId: string;
  identityId: string;
  kind: "agent" | "token" | "key";
  subjectId: string;
  revokedAt: string;
  payloadHash: string;
  witnessKeyId: string;
  signature: string;
}
```

Implement a local witness service that signs the receipt with Ed25519 and stores a digest index.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test packages/protocol/test/witness.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/witness.ts packages/protocol/src/types.ts packages/protocol/src/registry.ts apps/api/src/app.ts packages/protocol/test/witness.test.ts apps/api/test/hardening.test.ts
git commit -m "add revocation witness receipts"
```

### Task 3: Replace demo key export with custody abstractions

**Files:**

- Create: `packages/protocol/src/custody.ts`
- Modify: `packages/protocol/src/types.ts`
- Modify: `packages/protocol/src/registry.ts`
- Modify: `apps/api/src/app.ts`
- Modify: `apps/api/src/index.ts`
- Test: `apps/api/test/hardening.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from "vitest";
import { createLocalDevKeyCustody } from "@home/protocol";

describe("key custody", () => {
  it("does not export private keys in production mode", async () => {
    const custody = createLocalDevKeyCustody({ allowPrivateKeyExport: false });
    await expect(custody.exportPrivateKey("root")).rejects.toThrow(/disabled/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test apps/api/test/hardening.test.ts`
Expected: missing export or failing assertion before the custody abstraction exists.

- [ ] **Step 3: Write minimal implementation**

Introduce a custody interface:

```ts
export interface KeyCustodyProvider {
  createRootKey(identityId: string): Promise<PrivateKeyMaterial>;
  createAgentKey(
    identityId: string,
    agentId: string,
  ): Promise<PrivateKeyMaterial>;
  sign(payload: unknown, keyId: string): Promise<string>;
  exportPrivateKey(keyId: string): Promise<string>;
}
```

Make the local dev provider refuse export unless explicitly enabled outside production, and wire the API to only return public metadata by default.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test apps/api/test/hardening.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/custody.ts packages/protocol/src/types.ts packages/protocol/src/registry.ts apps/api/src/app.ts apps/api/src/index.ts apps/api/test/hardening.test.ts
git commit -m "add explicit key custody boundaries"
```

### Task 4: Normalize generated OpenAPI output for stable SDK components

**Files:**

- Create: `apps/api/src/openapi.ts`
- Modify: `apps/api/src/app.ts`
- Test: `apps/api/test/hardening.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from "vitest";
import { normalizeOpenApiDocument } from "../src/openapi.js";

describe("openapi normalization", () => {
  it("maps generated component ids to stable schema names", () => {
    const normalized = normalizeOpenApiDocument({
      openapi: "3.0.3",
      info: { title: "x", version: "1" },
      paths: {},
      components: {
        schemas: {
          "def-0": { type: "object", properties: { ok: { type: "boolean" } } },
        },
      },
    });

    expect(normalized.components?.schemas?.IdentityManifest).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test apps/api/test/hardening.test.ts`
Expected: failing assertion or missing export before the post-processor exists.

- [ ] **Step 3: Write minimal implementation**

Implement a pure post-processor:

```ts
export function normalizeOpenApiDocument(doc: OpenApiObject): OpenApiObject {
  return {
    ...doc,
    components: {
      ...doc.components,
      schemas: renameGeneratedSchemas(doc.components?.schemas ?? {}),
    },
  };
}
```

Make the output map the generated anonymous schema ids onto stable names used by the SDK and docs.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test apps/api/test/hardening.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/openapi.ts apps/api/src/app.ts apps/api/test/hardening.test.ts
git commit -m "normalize openapi output for sdk generation"
```

### Task 5: Re-run the full verification gate

**Files:**

- No new files expected

- [ ] **Step 1: Run the full checks**

Run:

```bash
pnpm typecheck
pnpm test
pnpm demo
```

Expected:

- `pnpm typecheck` exits 0
- `pnpm test` exits 0
- `pnpm demo` exits 0 and prints the two demo scenarios

- [ ] **Step 2: Inspect the OpenAPI output**

Run:

```bash
pnpm exec tsx --eval \"(async () => { const { mkdtemp } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const { LocalJsonStore } = await import('./packages/protocol/src/index.js'); const { buildApp } = await import('./apps/api/src/app.js'); const dir = await mkdtemp(join(tmpdir(), 'home-openapi-check-')); const app = buildApp(new LocalJsonStore(dir)); await app.ready(); const spec = app.swagger(); console.log(Object.keys(spec.components?.schemas ?? {})); await app.close(); })().catch((error) => { console.error(error); process.exit(1); });\"
```

Expected: stable schema names, not only anonymous generator ids.

- [ ] **Step 3: Final cleanup**

If any test failed, fix the implementation and re-run the full checks. Do not stop at partial success.
