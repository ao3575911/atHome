import { describe, expect, it } from "vitest";
import {
  createEd25519Signer,
  generateEd25519IdentityKey,
} from "@athome/identity-core";
import {
  createCreatorProofDraft,
  signCreatorProof,
  verifyCreatorProof,
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
});
