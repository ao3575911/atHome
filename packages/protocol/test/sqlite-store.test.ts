import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  IdentityRegistry,
  SQLiteRegistryBackend,
  createMemoryWitnessService,
} from "../src/index.js";

const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as {
  DatabaseSync: new (
    path: string,
    options?: { readOnly?: boolean | undefined },
  ) => {
    prepare(sql: string): {
      all(...values: unknown[]): Record<string, unknown>[];
    };
    close(): void;
  };
};

async function createTempDatabase() {
  const dir = await mkdtemp(join(tmpdir(), "home-sqlite-backend-"));
  return {
    dir,
    databasePath: join(dir, "registry.sqlite"),
  };
}

describe("sqlite registry backend", () => {
  it("creates the protocol registry schema", async () => {
    const { dir, databasePath } = await createTempDatabase();
    const backend = new SQLiteRegistryBackend(databasePath);

    try {
      backend.init();
      backend.close();

      const db = new DatabaseSync(databasePath, { readOnly: true });
      try {
        const tables = db
          .prepare(
            `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`,
          )
          .all()
          .map((row) => String(row.name));

        expect(tables).toEqual(
          expect.arrayContaining([
            "namespaces",
            "identity_manifests",
            "private_identity_records",
            "public_keys",
            "services",
            "agents",
            "capability_tokens",
            "revocations",
            "registry_events",
            "witness_receipts",
            "replay_nonces",
            "abuse_reviews",
          ]),
        );
      } finally {
        db.close();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("persists manifests, private records, events, revocations, receipts, and replay nonces", async () => {
    const { dir, databasePath } = await createTempDatabase();
    const backend = new SQLiteRegistryBackend(databasePath, {
      namespaceId: "local-dev",
    });
    const registry = new IdentityRegistry(
      backend,
      undefined,
      createMemoryWitnessService(),
    );

    try {
      await registry.createIdentity("sqlite@home");

      expect(await backend.listIdentityIds()).toEqual(["sqlite@home"]);
      expect(await backend.readManifest("sqlite@home")).toMatchObject({
        id: "sqlite@home",
        signatureKeyId: "root",
      });
      expect(await backend.readPrivateRecord("sqlite@home")).toMatchObject({
        id: "sqlite@home",
      });

      await registry.registerService("sqlite@home", {
        id: "inbox@sqlite",
        type: "inbox",
        endpoint: "http://localhost:8787/inbox",
        capabilities: ["email:draft"],
      });

      await registry.registerAgent("sqlite@home", {
        id: "assistant@sqlite",
        allowedCapabilities: ["profile:read", "email:draft"],
        deniedCapabilities: ["payment:send"],
      });

      const token = await registry.issueCapabilityToken("sqlite@home", {
        subject: "assistant@sqlite",
        permissions: ["email:draft"],
        ttlSeconds: 3600,
      });

      await registry.revokeCapabilityToken("sqlite@home", token.id);

      const events = await backend.listEvents("sqlite@home");
      expect(events.length).toBeGreaterThan(0);
      expect(events.at(-1)?.hash).toBeTypeOf("string");

      const revocation = await backend.getRevocationState("sqlite@home");
      expect(revocation).not.toBeNull();
      expect(revocation?.revokedCapabilityTokens[token.id]).toBeDefined();

      const receipts = await backend.listWitnessReceipts("sqlite@home");
      expect(receipts.length).toBeGreaterThan(0);
      expect(receipts[0]).toMatchObject({
        identityId: "sqlite@home",
        eventId: expect.any(String),
      });

      await backend.recordNonce(
        "verify-request",
        "nonce-123",
        "2030-01-01T00:00:00.000Z",
      );
      expect(await backend.hasNonce("verify-request", "nonce-123")).toBe(true);
      expect(await backend.hasNonce("verify-request", "missing")).toBe(false);

      backend.close();
      const reopened = new SQLiteRegistryBackend(databasePath, {
        namespaceId: "local-dev",
      });
      try {
        expect(await reopened.readManifest("sqlite@home")).toMatchObject({
          id: "sqlite@home",
        });
        expect(await reopened.readPrivateRecord("sqlite@home")).toMatchObject({
          id: "sqlite@home",
        });
        expect(await reopened.listEvents("sqlite@home")).toHaveLength(
          events.length,
        );
        expect(await reopened.hasNonce("verify-request", "nonce-123")).toBe(
          true,
        );
      } finally {
        reopened.close();
      }
    } finally {
      try {
        backend.close();
      } catch {
        // The persistence assertion closes and reopens this handle.
      }
      await rm(dir, { recursive: true, force: true });
    }
  });
});
