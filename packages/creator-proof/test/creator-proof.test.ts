import { describe, expect, it } from "vitest";
import {
  createEd25519Signer,
  generateEd25519IdentityKey,
} from "@athome/identity-core";
import {
  createCreatorProofDraft,
  signCreatorProof,
  verifyCreatorProof,
  createCreatorProofPolicy,
} from "../src/index.js";

describe("creator proofs", () => {
  it("verifies an anchored creator-control proof and rejects failures", async () => {
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
        claims: [{ type: "creator.control", value: true }],
        issuedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-02T00:00:00.000Z",
        nonce: "proof-nonce",
      }),
      createEd25519Signer({ keyId: key.id, privateKey }),
    );
    const trusted = {
      trustAnchors: [{ issuer: "creator@atHome", key }],
      now: new Date("2026-01-01T12:00:00.000Z"),
    };

    expect(verifyCreatorProof({ proof, ...trusted })).toMatchObject({
      ok: true,
      proof: { id: "proof-1" },
    });
    expect(
      verifyCreatorProof({
        proof: { ...proof, subject: "other@creator" },
        ...trusted,
      }),
    ).toMatchObject({ ok: false, code: "signature_invalid" });
    expect(
      verifyCreatorProof({ proof, trustAnchors: [], now: trusted.now }),
    ).toMatchObject({ ok: false, code: "untrusted_issuer" });
    expect(
      verifyCreatorProof({
        proof,
        trustAnchors: [
          {
            issuer: "creator@atHome",
            key: { ...key, expiresAt: "2026-01-01T06:00:00.000Z" },
          },
        ],
        now: trusted.now,
      }),
    ).toMatchObject({ ok: false, code: "signature_invalid" });
    expect(
      verifyCreatorProof({
        proof,
        ...trusted,
        now: new Date("2026-01-03T00:00:00.000Z"),
      }),
    ).toMatchObject({ ok: false, code: "proof_expired" });
    expect(
      verifyCreatorProof({
        proof,
        ...trusted,
        revokedProofIds: new Set(["proof-1"]),
      }),
    ).toMatchObject({ ok: false, code: "proof_revoked" });
    for (const value of [false, null]) {
      const relationshipProof = {
        ...proof,
        claims: [{ type: "creator.control", value }],
      };
      expect(
        verifyCreatorProof({ proof: relationshipProof, ...trusted }),
      ).toMatchObject({ ok: false, code: "creator_relationship_missing" });
    }
    expect(() =>
      createCreatorProofDraft({
        version: "a1",
        id: "proof-non-iso",
        issuer: "creator@atHome",
        subject: "agent@creator",
        claims: [{ type: "creator.control", value: true }],
        issuedAt: "01/02/2026",
      }),
    ).toThrow();
  });

  it.each([false, null])(
    "rejects a signed non-affirmative creator relationship claim (%s)",
    async (value) => {
      const { key, privateKey } = generateEd25519IdentityKey({
        id: "creator-root",
        purpose: "root",
        createdAt: new Date("2026-01-01T00:00:00.000Z"),
      });
      const proof = await signCreatorProof(
        createCreatorProofDraft({
          version: "a1",
          id: "proof-non-affirmative",
          issuer: "creator@atHome",
          subject: "agent@creator",
          claims: [{ type: "creator.control", value }],
          issuedAt: "2026-01-01T00:00:00.000Z",
          expiresAt: "2026-01-02T00:00:00.000Z",
        }),
        createEd25519Signer({ keyId: key.id, privateKey }),
      );

      expect(
        verifyCreatorProof({
          proof,
          trustAnchors: [{ issuer: "creator@atHome", key }],
          now: new Date("2026-01-01T12:00:00.000Z"),
        }),
      ).toMatchObject({ ok: false, code: "creator_relationship_missing" });
    },
  );

  it("binds a creator proof to the authenticated owner", async () => {
    const { key, privateKey } = generateEd25519IdentityKey({
      id: "creator-root",
      purpose: "root",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    const proof = await signCreatorProof(
      createCreatorProofDraft({
        version: "a1",
        id: "proof-owner",
        issuer: "owner-a",
        subject: "agent",
        claims: [{ type: "creator.control", value: true }],
        issuedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-02T00:00:00.000Z",
      }),
      createEd25519Signer({ keyId: key.id, privateKey }),
    );
    const policy = createCreatorProofPolicy({
      trustAnchors: [{ issuer: "owner-a", key }],
      now: () => new Date("2026-01-01T12:00:00.000Z"),
    });

    expect(
      policy.evaluate({
        manifest: { id: "owner-b" } as never,
        request: { actor: "agent" } as never,
        requestedPermission: "email:draft",
        context: { creatorProof: proof },
      }),
    ).toMatchObject({ ok: false, code: "creator_proof_invalid" });
  });
});
