import { describe, expect, it } from "vitest";
import {
  createIdentityManifestDraft,
  createMemoryKeyCustodyProvider,
  createMemoryRegistryBackend,
  createMemoryWitnessService,
  createRegistryEventDraft,
  generateEd25519KeyPair,
  signIdentityManifest,
  signRegistryEvent,
  verifyCanonicalPayload,
} from "../src/index.js";

async function seedIdentity(
  backend: ReturnType<typeof createMemoryRegistryBackend>,
  id = "krav@home",
) {
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

    const stored = await backend.appendEvent("krav@home", event);
    expect(stored.identityId).toBe("krav@home");

    const revocation = await backend.getRevocationState("krav@home");
    expect(revocation).not.toBeNull();
    expect(revocation!.revokedCapabilityTokens["token-123"]).toBeDefined();
    expect((await backend.listEvents("krav@home"))[0]?.hash).toBeDefined();
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
      backend.appendEvent("krav@home", {
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
    await backend.appendEvent("krav@home", firstEvent);

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

    await expect(backend.appendEvent("krav@home", secondEvent)).rejects.toThrow(
      /previous hash/i,
    );
  });
});

describe("witness receipts", () => {
  it("signs and verifies append-only registry receipts", async () => {
    const backend = createMemoryRegistryBackend();
    const witness = createMemoryWitnessService();
    const { rootPrivateKey } = await seedIdentity(backend);

    const event = await backend.appendEvent(
      "krav@home",
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
      identityId: "krav@home",
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

    await backend.attachWitnessReceipt("krav@home", receipt);
    expect((await backend.listWitnessReceipts("krav@home"))[0]).toMatchObject({
      eventId: event.id,
      identityId: "krav@home",
    });
  });
});

describe("key custody provider", () => {
  it("keeps private keys inside custody while still supporting signing and rotation", async () => {
    const custody = createMemoryKeyCustodyProvider();

    const root = await custody.provisionKey({
      identityId: "krav@home",
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
      identityId: "krav@home",
      keyId: "root",
      payload,
    });
    expect(verifyCanonicalPayload(payload, signature, root.publicKey)).toBe(
      true,
    );

    const rotated = await custody.rotateKey({
      identityId: "krav@home",
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
        identityId: "krav@home",
        keyId: "root",
      }),
    ).rejects.toThrow(/disabled/i);
  });
});
