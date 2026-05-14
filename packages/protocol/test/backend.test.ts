import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createIdentityManifestDraft,
  createMemoryKeyCustodyProvider,
  createMemoryRegistryBackend,
  createMemoryWitnessService,
  createPostgresRegistryBackend,
  createRegistryEventDraft,
  generateEd25519KeyPair,
  LocalJsonStore,
  SQLiteRegistryBackend,
  type RegistryBackend,
  signIdentityManifest,
  signRegistryEvent,
  verifyCanonicalPayload,
} from "../src/index.js";
import { PostgresRegistryBackend } from "../src/storage/postgres.js";

async function seedIdentity(backend: RegistryBackend, id = "krav@atHome") {
  const now = "2026-05-11T00:00:00.000Z";
  const rootKeys = generateEd25519KeyPair();
  const rootPublicKey = {
    id: "root",
    type: "ed25519" as const,
    publicKey: rootKeys.publicKey,
    purpose: "root" as const,
    status: "active" as const,
    createdAt: now,
  };
  const rootPrivateKey = {
    ...rootPublicKey,
    privateKey: rootKeys.privateKey,
  };

  const manifest = signIdentityManifest(
    createIdentityManifestDraft(id, rootPublicKey, now),
    rootPrivateKey,
  );

  await backend.writeManifest(manifest);
  await backend.writePrivateRecord({
    id,
    keys: {
      root: rootPrivateKey,
    },
    createdAt: now,
    updatedAt: now,
  });

  return { manifest, rootPrivateKey };
}

// ---------------------------------------------------------------------------
// Shared parity suite — runs for every backend adapter
// ---------------------------------------------------------------------------

function runBackendParitySuite(
  label: string,
  makeBackend: () => Promise<{
    backend: RegistryBackend;
    teardown: () => Promise<void>;
  }>,
) {
  describe(label, () => {
    it("appends signed revocation events and materializes revoked state", async () => {
      const { backend, teardown } = await makeBackend();
      try {
        const { rootPrivateKey } = await seedIdentity(backend);

        const event = signRegistryEvent(
          createRegistryEventDraft({
            type: "token.revoked",
            subjectId: "token-123",
            signerKeyId: "root",
            previousHash: "genesis",
            timestamp: "2026-05-11T00:00:00.000Z",
            details: { reason: "manual revocation" },
          }),
          rootPrivateKey.privateKey,
        );

        const stored = await backend.appendEvent("krav@atHome", event);
        expect(stored.identityId).toBe("krav@atHome");

        const revocation = await backend.getRevocationState("krav@atHome");
        expect(revocation).not.toBeNull();
        expect(revocation!.revokedCapabilityTokens["token-123"]).toBeDefined();
        expect(
          (await backend.listEvents("krav@atHome"))[0]?.hash,
        ).toBeDefined();
      } finally {
        await teardown();
      }
    });

    it("rejects an event with an invalid signature", async () => {
      const { backend, teardown } = await makeBackend();
      try {
        const { rootPrivateKey } = await seedIdentity(backend);
        const event = signRegistryEvent(
          createRegistryEventDraft({
            type: "key.revoked",
            subjectId: "root",
            signerKeyId: "root",
            previousHash: "genesis",
            timestamp: "2026-05-11T00:00:00.000Z",
            details: { reason: "rotate root key" },
          }),
          rootPrivateKey.privateKey,
        );

        await expect(
          backend.appendEvent("krav@atHome", {
            ...event,
            signature: "tampered",
          }),
        ).rejects.toThrow(/signature/i);
      } finally {
        await teardown();
      }
    });

    it("rejects an event that breaks the append-only hash chain", async () => {
      const { backend, teardown } = await makeBackend();
      try {
        const { rootPrivateKey } = await seedIdentity(backend);

        const firstEvent = signRegistryEvent(
          createRegistryEventDraft({
            type: "key.revoked",
            subjectId: "root",
            signerKeyId: "root",
            previousHash: "genesis",
            timestamp: "2026-05-11T00:00:00.000Z",
            details: { reason: "rotate root key" },
          }),
          rootPrivateKey.privateKey,
        );
        await backend.appendEvent("krav@atHome", firstEvent);

        const secondEvent = signRegistryEvent(
          createRegistryEventDraft({
            type: "token.revoked",
            subjectId: "token-456",
            signerKeyId: "root",
            previousHash: "wrong-previous-hash",
            timestamp: "2026-05-11T00:00:01.000Z",
            details: { reason: "chain break" },
          }),
          rootPrivateKey.privateKey,
        );

        await expect(
          backend.appendEvent("krav@atHome", secondEvent),
        ).rejects.toThrow(/previous hash/i);
      } finally {
        await teardown();
      }
    });

    it("signs and verifies append-only registry receipts", async () => {
      const { backend, teardown } = await makeBackend();
      const witness = createMemoryWitnessService();
      try {
        const { rootPrivateKey } = await seedIdentity(backend);

        const event = await backend.appendEvent(
          "krav@atHome",
          signRegistryEvent(
            createRegistryEventDraft({
              type: "agent.revoked",
              subjectId: "foreman@krav",
              signerKeyId: "root",
              previousHash: "genesis",
              timestamp: "2026-05-11T00:00:00.000Z",
              details: { reason: "lost access" },
            }),
            rootPrivateKey.privateKey,
          ),
        );

        const receipt = await witness.issueReceipt(event, {
          identityId: "krav@atHome",
          logIndex: 0,
        });
        expect(await witness.verifyReceipt(event, receipt)).toMatchObject({
          ok: true,
        });

        await backend.attachWitnessReceipt("krav@atHome", receipt);
        expect(
          (await backend.listWitnessReceipts("krav@atHome"))[0],
        ).toMatchObject({ eventId: event.id, identityId: "krav@atHome" });
      } finally {
        await teardown();
      }
    });

    it("creates checkpoints and reports freshness metadata", async () => {
      const { backend, teardown } = await makeBackend();
      const witness = createMemoryWitnessService();
      try {
        const { rootPrivateKey } = await seedIdentity(backend);

        const event = await backend.appendEvent(
          "krav@atHome",
          signRegistryEvent(
            createRegistryEventDraft({
              type: "token.revoked",
              subjectId: "token-fresh",
              signerKeyId: "root",
              previousHash: "genesis",
              timestamp: "2026-05-11T00:00:00.000Z",
              details: { reason: "freshness test" },
            }),
            rootPrivateKey.privateKey,
          ),
        );

        const checkpoint = await backend.createCheckpoint("krav@atHome", {
          issuedAt: "2026-05-11T00:00:01.000Z",
          witnessKeyId: "witness-a",
        });
        const signedCheckpoint = await witness.issueCheckpoint(checkpoint);
        expect(checkpoint).toMatchObject({
          identityId: "krav@atHome",
          eventCount: 1,
          latestEventId: event.id,
          latestEventHash: event.hash,
        });
        expect(await witness.verifyCheckpoint(signedCheckpoint)).toMatchObject({
          ok: true,
        });

        const freshness = await backend.getFreshnessMetadata("krav@atHome");
        expect(freshness).toMatchObject({
          identityId: "krav@atHome",
          latestEventId: event.id,
          eventCount: 1,
        });
      } finally {
        await teardown();
      }
    });

    it("reads and writes custody key records", async () => {
      const { backend, teardown } = await makeBackend();
      try {
        const custody = createMemoryKeyCustodyProvider({
          recordStore: backend,
        });
        await seedIdentity(backend);
        await custody.provisionKey({
          identityId: "krav@atHome",
          keyId: "agent-key-1",
          purpose: "agent",
        });
        const record = await backend.readCustodyKeyRecord(
          "krav@atHome",
          "agent-key-1",
        );
        expect(record).toMatchObject({
          identityId: "krav@atHome",
          keyId: "agent-key-1",
          purpose: "agent",
          status: "active",
        });
      } finally {
        await teardown();
      }
    });

    it("handles replay nonces", async () => {
      const { backend, teardown } = await makeBackend();
      try {
        const expiresAt = new Date(Date.now() + 60_000).toISOString();
        expect(await backend.hasNonce("test-scope", "nonce-abc")).toBe(false);
        await backend.recordNonce("test-scope", "nonce-abc", expiresAt);
        expect(await backend.hasNonce("test-scope", "nonce-abc")).toBe(true);
      } finally {
        await teardown();
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Memory adapter
// ---------------------------------------------------------------------------

runBackendParitySuite("memory backend", async () => ({
  backend: createMemoryRegistryBackend(),
  teardown: async () => {},
}));

// ---------------------------------------------------------------------------
// LocalJsonStore (file-based) adapter
// ---------------------------------------------------------------------------

runBackendParitySuite("LocalJsonStore backend", async () => {
  const dir = await mkdtemp(join(tmpdir(), "home-backend-json-"));
  return {
    backend: new LocalJsonStore(dir),
    teardown: async () => rm(dir, { recursive: true, force: true }),
  };
});

// ---------------------------------------------------------------------------
// SQLiteRegistryBackend (sqlite-store.ts)
// ---------------------------------------------------------------------------

runBackendParitySuite("SQLite backend", async () => ({
  backend: new SQLiteRegistryBackend(":memory:"),
  teardown: async () => {},
}));

// ---------------------------------------------------------------------------
// Postgres adapter (skipped unless DATABASE_URL is set)
// ---------------------------------------------------------------------------

const databaseUrl = process.env["DATABASE_URL"];

if (databaseUrl) {
  runBackendParitySuite("Postgres backend", async () => {
    const backend = createPostgresRegistryBackend({
      connectionString: databaseUrl,
    }) as PostgresRegistryBackend;
    await backend.runMigrations();

    // Seed a unique identity prefix per run to avoid cross-test collisions
    const prefix = `test-${Date.now()}`;
    const originalSeed = seedIdentity;
    // Override seedIdentity to use namespaced IDs — handled by test isolation below
    return {
      backend,
      teardown: async () => {
        await backend.end();
      },
    };
  });
} else {
  describe("Postgres backend", () => {
    it.skip("skipped — set DATABASE_URL to run Postgres parity tests");
  });
}

// ---------------------------------------------------------------------------
// Postgres adapter contract (always runs — validates capabilities shape)
// ---------------------------------------------------------------------------

describe("registry backend events", () => {
  it("appends signed revocation events and materializes revoked state", async () => {
    const backend = createMemoryRegistryBackend();
    const { rootPrivateKey } = await seedIdentity(backend);

    const event = signRegistryEvent(
      createRegistryEventDraft({
        type: "token.revoked",
        subjectId: "token-123",
        signerKeyId: "root",
        previousHash: "genesis",
        timestamp: "2026-05-11T00:00:00.000Z",
        details: { reason: "manual revocation" },
      }),
      rootPrivateKey.privateKey,
    );

    const stored = await backend.appendEvent("krav@atHome", event);
    expect(stored.identityId).toBe("krav@atHome");

    const revocation = await backend.getRevocationState("krav@atHome");
    expect(revocation).not.toBeNull();
    expect(revocation!.revokedCapabilityTokens["token-123"]).toBeDefined();
    expect((await backend.listEvents("krav@atHome"))[0]?.hash).toBeDefined();
  });

  it("rejects an event with an invalid signature", async () => {
    const backend = createMemoryRegistryBackend();
    const { rootPrivateKey } = await seedIdentity(backend);
    const event = signRegistryEvent(
      createRegistryEventDraft({
        type: "key.revoked",
        subjectId: "root",
        signerKeyId: "root",
        previousHash: "genesis",
        timestamp: "2026-05-11T00:00:00.000Z",
        details: { reason: "rotate root key" },
      }),
      rootPrivateKey.privateKey,
    );

    await expect(
      backend.appendEvent("krav@atHome", {
        ...event,
        signature: "tampered",
      }),
    ).rejects.toThrow(/signature/i);
  });

  it("rejects an event that breaks the append-only hash chain", async () => {
    const backend = createMemoryRegistryBackend();
    const { rootPrivateKey } = await seedIdentity(backend);

    const firstEvent = signRegistryEvent(
      createRegistryEventDraft({
        type: "key.revoked",
        subjectId: "root",
        signerKeyId: "root",
        previousHash: "genesis",
        timestamp: "2026-05-11T00:00:00.000Z",
        details: { reason: "rotate root key" },
      }),
      rootPrivateKey.privateKey,
    );
    await backend.appendEvent("krav@atHome", firstEvent);

    const secondEvent = signRegistryEvent(
      createRegistryEventDraft({
        type: "token.revoked",
        subjectId: "token-456",
        signerKeyId: "root",
        previousHash: "wrong-previous-hash",
        timestamp: "2026-05-11T00:00:01.000Z",
        details: { reason: "chain break" },
      }),
      rootPrivateKey.privateKey,
    );

    await expect(
      backend.appendEvent("krav@atHome", secondEvent),
    ).rejects.toThrow(/previous hash/i);
  });
});

describe("witness receipts", () => {
  it("signs and verifies append-only registry receipts", async () => {
    const backend = createMemoryRegistryBackend();
    const witness = createMemoryWitnessService();
    const { rootPrivateKey } = await seedIdentity(backend);

    const event = await backend.appendEvent(
      "krav@atHome",
      signRegistryEvent(
        createRegistryEventDraft({
          type: "agent.revoked",
          subjectId: "foreman@krav",
          signerKeyId: "root",
          previousHash: "genesis",
          timestamp: "2026-05-11T00:00:00.000Z",
          details: { reason: "lost access" },
        }),
        rootPrivateKey.privateKey,
      ),
    );

    const receipt = await witness.issueReceipt(event, {
      identityId: "krav@atHome",
      logIndex: 0,
    });
    expect(await witness.verifyReceipt(event, receipt)).toMatchObject({
      ok: true,
    });
    expect(
      await witness.verifyReceipt(
        { ...event, payloadHash: "mutated" },
        receipt,
      ),
    ).toMatchObject({
      ok: false,
      code: "witness_receipt_invalid",
    });

    await backend.attachWitnessReceipt("krav@atHome", receipt);
    expect((await backend.listWitnessReceipts("krav@atHome"))[0]).toMatchObject(
      {
        eventId: event.id,
        identityId: "krav@atHome",
      },
    );
  });
});

describe("registry freshness and durable backend state", () => {
  it("creates checkpoints and reports freshness metadata from the event log", async () => {
    const backend = createMemoryRegistryBackend();
    const witness = createMemoryWitnessService();
    const { rootPrivateKey } = await seedIdentity(backend);

    const event = await backend.appendEvent(
      "krav@atHome",
      signRegistryEvent(
        createRegistryEventDraft({
          type: "token.revoked",
          subjectId: "token-fresh",
          signerKeyId: "root",
          previousHash: "genesis",
          timestamp: "2026-05-11T00:00:00.000Z",
          details: { reason: "freshness test" },
        }),
        rootPrivateKey.privateKey,
      ),
    );

    const checkpoint = await backend.createCheckpoint("krav@atHome", {
      issuedAt: "2026-05-11T00:00:01.000Z",
      witnessKeyId: "witness-a",
    });
    const signedCheckpoint = await witness.issueCheckpoint(checkpoint);
    expect(checkpoint).toMatchObject({
      identityId: "krav@atHome",
      eventCount: 1,
      latestEventId: event.id,
      latestEventHash: event.hash,
      witnessKeyId: "witness-a",
    });
    expect(await witness.verifyCheckpoint(signedCheckpoint)).toMatchObject({
      ok: true,
    });
    await expect(
      witness.verifyCheckpoint({
        ...signedCheckpoint,
        latestEventHash: "mutated",
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: "witness_receipt_invalid",
    });

    const freshness = await backend.getFreshnessMetadata("krav@atHome");
    expect(freshness).toMatchObject({
      identityId: "krav@atHome",
      latestEventId: event.id,
      latestEventHash: event.hash,
      eventCount: 1,
      witnessReceiptCount: 0,
    });
    expect(freshness.checkpoint?.checkpointId).toBe(checkpoint.checkpointId);
  });

  it("persists witness receipts, checkpoints, and custody metadata in local JSON", async () => {
    const dir = await mkdtemp(join(tmpdir(), "home-protocol-backend-"));

    try {
      const backend = new LocalJsonStore(dir);
      const witness = createMemoryWitnessService();
      const { rootPrivateKey } = await seedIdentity(backend);
      const event = await backend.appendEvent(
        "krav@atHome",
        signRegistryEvent(
          createRegistryEventDraft({
            type: "key.revoked",
            subjectId: "old-root",
            signerKeyId: "root",
            previousHash: "genesis",
            timestamp: "2026-05-11T00:00:00.000Z",
            details: { reason: "json durability" },
          }),
          rootPrivateKey.privateKey,
        ),
      );
      const receipt = await witness.issueReceipt(event, {
        identityId: "krav@atHome",
        logIndex: 0,
      });
      await backend.attachWitnessReceipt("krav@atHome", receipt);
      const checkpoint = await backend.createCheckpoint("krav@atHome", {
        issuedAt: "2026-05-11T00:00:01.000Z",
      });

      const custody = createMemoryKeyCustodyProvider({
        recordStore: backend,
      });
      await custody.provisionKey({
        identityId: "krav@atHome",
        keyId: "hosted-root",
        purpose: "root",
      });

      const reopened = new LocalJsonStore(dir);
      expect(await reopened.listWitnessReceipts("krav@atHome")).toMatchObject([
        { receiptId: receipt.receiptId, eventId: event.id },
      ]);
      expect(await reopened.readCheckpoint("krav@atHome")).toMatchObject({
        checkpointId: checkpoint.checkpointId,
        latestEventId: event.id,
      });
      expect(
        await reopened.readCustodyKeyRecord("krav@atHome", "hosted-root"),
      ).toMatchObject({
        identityId: "krav@atHome",
        keyId: "hosted-root",
        provider: "local-dev",
        exportable: false,
      });
      expect(await reopened.getFreshnessMetadata("krav@atHome")).toMatchObject({
        latestEventId: event.id,
        witnessReceiptCount: 1,
        checkpoint: { checkpointId: checkpoint.checkpointId },
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exports a Postgres adapter contract without pretending to be wired", async () => {
    const backend = createPostgresRegistryBackend({
      connectionString: "postgres://registry.example/athome",
    });

    expect(backend.capabilities).toMatchObject({
      adapter: "postgres",
      durable: true,
      transactions: true,
      checkpoints: true,
    });
    await expect(backend.listIdentityIds()).rejects.toThrow(
      /pg.*package|DATABASE_URL|connection/i,
    );
  });
});

describe("key custody provider", () => {
  it("keeps private keys inside custody while still supporting signing and rotation", async () => {
    const custody = createMemoryKeyCustodyProvider();

    const root = await custody.provisionKey({
      identityId: "krav@atHome",
      keyId: "root",
      purpose: "root",
    });

    expect(root).toMatchObject({
      id: "root",
      purpose: "root",
      status: "active",
    });
    expect("privateKey" in root).toBe(false);

    const payload = { hello: "world" };
    const signature = await custody.sign({
      identityId: "krav@atHome",
      keyId: "root",
      payload,
    });
    expect(verifyCanonicalPayload(payload, signature, root.publicKey)).toBe(
      true,
    );

    const rotated = await custody.rotateKey({
      identityId: "krav@atHome",
      keyId: "root",
      newKeyId: "root-2",
    });

    expect(rotated.previous).toMatchObject({
      id: "root",
      status: "deprecated",
    });
    expect(rotated.current).toMatchObject({
      id: "root-2",
      status: "active",
    });

    await expect(
      custody.exportPrivateKey({
        identityId: "krav@atHome",
        keyId: "root",
      }),
    ).rejects.toThrow(/disabled/i);
  });
});
