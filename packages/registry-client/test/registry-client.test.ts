import { describe, expect, it } from "vitest";
import {
  createEd25519Signer,
  generateEd25519IdentityKey,
} from "@athome/identity-core";
import {
  createCreatorProofDraft,
  signCreatorProof,
} from "@athome/creator-proof";
import { CreatorRegistryClient } from "../src/index.js";

async function createProof() {
  const { key, privateKey } = generateEd25519IdentityKey({
    id: "creator-root",
    purpose: "root",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
  });
  const proof = await signCreatorProof(
    createCreatorProofDraft({
      version: "a1",
      id: "proof-1",
      issuer: "creator@atHome",
      subject: "agent@creator",
      subjectOwner: "creator@atHome",
      claims: [{ type: "creator.control", value: true }],
      issuedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-02T00:00:00.000Z",
    }),
    createEd25519Signer({ keyId: key.id, privateKey }),
  );
  return { proof, trustAnchors: [{ issuer: "creator@atHome", key }] };
}

describe("creator registry client", () => {
  it("verifies returned records locally and reports safe failure states", async () => {
    const { proof, trustAnchors } = await createProof();
    const now = new Date("2026-01-01T12:00:00.000Z");
    const client = new CreatorRegistryClient({
      baseUrl: "https://registry.example.test",
      now: () => now,
      fetch: async (url) => {
        expect(String(url)).toBe(
          "https://registry.example.test/v1/creator-proofs/agent%40creator",
        );
        return new Response(
          JSON.stringify({
            proof,
            updatedAt: "2026-01-01T11:30:00.000Z",
          }),
        );
      },
    });

    await expect(
      client.resolve({ subject: "agent@creator", trustAnchors }),
    ).resolves.toMatchObject({ ok: true, proof: { id: "proof-1" } });

    const staleClient = new CreatorRegistryClient({
      baseUrl: "https://registry.example.test",
      now: () => now,
      maxStalenessMs: 1_000,
      fetch: async () =>
        new Response(
          JSON.stringify({
            proof,
            updatedAt: "2026-01-01T00:00:00.000Z",
          }),
        ),
    });
    await expect(
      staleClient.resolve({ subject: "agent@creator", trustAnchors }),
    ).resolves.toMatchObject({ ok: false, status: "stale" });

    const unavailableClient = new CreatorRegistryClient({
      baseUrl: "https://registry.example.test",
      fetch: async () => {
        throw new TypeError("connection refused");
      },
    });
    await expect(
      unavailableClient.resolve({ subject: "agent@creator", trustAnchors }),
    ).resolves.toMatchObject({ ok: false, status: "unavailable" });

    const malformedClient = new CreatorRegistryClient({
      baseUrl: "https://registry.example.test",
      fetch: async () => new Response(JSON.stringify({})),
    });
    await expect(
      malformedClient.resolve({ subject: "agent@creator", trustAnchors }),
    ).resolves.toMatchObject({ ok: false, status: "untrusted" });

    await expect(
      client.resolve({ subject: "agent@creator", trustAnchors: [] }),
    ).resolves.toMatchObject({ ok: false, status: "untrusted" });

    const futureClient = new CreatorRegistryClient({
      baseUrl: "https://registry.example.test",
      now: () => now,
      fetch: async () =>
        new Response(
          JSON.stringify({
            proof,
            updatedAt: "3026-01-01T00:00:00.000Z",
          }),
        ),
    });
    await expect(
      futureClient.resolve({ subject: "agent@creator", trustAnchors }),
    ).resolves.toMatchObject({ ok: false, status: "untrusted" });
  });
});
