# Home Identity Routing Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working MVP for signed personal identities, agent authorization, capability tokens, and signed-request verification.

**Architecture:** Build the protocol first so every other surface shares one canonical signing and verification path. Keep the API as a thin Fastify wrapper over the protocol package, persist all local state in JSON files, and keep the SDK and demo scripts as consumers rather than owners of protocol logic.

**Tech Stack:** TypeScript, Node.js `node:crypto` Ed25519, Fastify, Zod, Vitest, pnpm workspaces.

---

### Task 1: Scaffold the workspace and shared type system

**Files:**

- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `tsconfig.json`
- Create: `.gitignore`
- Create: `packages/protocol/package.json`
- Create: `packages/protocol/tsconfig.json`
- Create: `packages/protocol/src/index.ts`
- Create: `packages/protocol/src/types.ts`
- Create: `packages/protocol/src/schemas.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from "vitest";
import { identityManifestSchema } from "@home/protocol";

describe("protocol schemas", () => {
  it("accepts a minimal signed manifest", () => {
    expect(
      identityManifestSchema.safeParse({
        id: "krav@home",
        version: "1.0.0",
        publicKeys: [],
        services: [],
        agents: [],
        claims: [],
        updatedAt: "2026-05-11T00:00:00.000Z",
        signature: "abc",
      }).success,
    ).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test -- --run tests/protocol.schema.test.ts`
Expected: module resolution or missing export failure before implementation exists.

- [ ] **Step 3: Write minimal implementation**

Implement the base type declarations and runtime schemas needed by the protocol package.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test`
Expected: the schema test passes.

- [ ] **Step 5: Commit**

```bash
git add package.json pnpm-workspace.yaml tsconfig.json .gitignore packages/protocol
git commit -m "establish workspace and protocol schema base"
```

### Task 2: Implement Ed25519 signing, canonical JSON, and local JSON storage

**Files:**

- Create: `packages/protocol/src/canonical.ts`
- Create: `packages/protocol/src/crypto.ts`
- Create: `packages/protocol/src/store.ts`
- Modify: `packages/protocol/src/index.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from "vitest";
import {
  canonicalize,
  generateEd25519KeyPair,
  signCanonicalPayload,
  verifyCanonicalPayload,
} from "@home/protocol";

describe("crypto utilities", () => {
  it("canonicalizes object keys deterministically", () => {
    expect(canonicalize({ b: 1, a: { d: 4, c: 3 } })).toBe(
      '{"a":{"c":3,"d":4},"b":1}',
    );
  });

  it("signs and verifies a payload", () => {
    const keys = generateEd25519KeyPair();
    const payload = { hello: "world" };
    const signature = signCanonicalPayload(payload, keys.privateKey);
    expect(verifyCanonicalPayload(payload, signature, keys.publicKey)).toBe(
      true,
    );
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test`
Expected: missing implementation failures.

- [ ] **Step 3: Write minimal implementation**

Implement stable JSON canonicalization, Ed25519 key generation/import/export, signature helpers, and atomic JSON file reads and writes.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test`
Expected: crypto tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/canonical.ts packages/protocol/src/crypto.ts packages/protocol/src/store.ts packages/protocol/src/index.ts
git commit -m "add canonical signing and local storage primitives"
```
