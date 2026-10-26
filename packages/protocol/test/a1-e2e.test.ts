import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createCreatorProofDraft,
  createCreatorProofPolicy,
  signCreatorProof,
} from "@athome/creator-proof";
import {
  createEd25519Signer,
  type IdentityKeyMaterial,
} from "@athome/identity-core";
import { IdentityRegistry, LocalJsonStore } from "../src/index.js";

describe("A1 identity and trust flow", () => {
  it("requires a verified creator proof only when the opt-in policy is used", async () => {
    const dir = await mkdtemp(join(tmpdir(), "home-a1-e2e-"));
    const registry = new IdentityRegistry(new LocalJsonStore(dir));

    try {
      const { rootKey } = await registry.createIdentity("creator@atHome");
      const agent = await registry.registerAgent("creator@atHome", {
        id: "agent@creator",
        allowedCapabilities: ["email:draft"],
        deniedCapabilities: [],
      });
      const token = await registry.issueCapabilityToken("creator@atHome", {
        subject: agent.agent.id,
        permissions: ["email:draft"],
        ttlSeconds: 3600,
      });
      const request = await registry.signRequest("creator@atHome", {
        actor: agent.agent.id,
        issuer: "creator@atHome",
        capabilityToken: token,
        method: "POST",
        path: "/emails/draft",
        body: { subject: "A1", message: "Proof-aware routing" },
      });
      const signingKey: IdentityKeyMaterial = {
        id: rootKey.id,
        algorithm: "Ed25519",
        encoding: "spki-der-base64",
        publicKey: rootKey.publicKey,
        purpose: rootKey.purpose,
        status: rootKey.status,
        createdAt: rootKey.createdAt,
      };
      const proof = await signCreatorProof(
        createCreatorProofDraft({
          version: "a1",
          id: "creator-proof-1",
          issuer: "creator@atHome",
          subject: agent.agent.id,
          claims: [{ type: "creator.control", value: true }],
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        }),
        createEd25519Signer({
          keyId: rootKey.id,
          privateKey: rootKey.privateKey,
        }),
      );
      const policy = createCreatorProofPolicy({
        trustAnchors: [{ issuer: "creator@atHome", key: signingKey }],
      });

      await expect(
        registry.verifyRequest("creator@atHome", request, {
          body: { subject: "A1", message: "Proof-aware routing" },
          policyHooks: [policy],
        }),
      ).resolves.toMatchObject({
        ok: false,
        code: "creator_proof_required",
      });

      await expect(
        registry.verifyRequest("creator@atHome", request, {
          body: { subject: "A1", message: "Proof-aware routing" },
          policyHooks: [policy],
          policyContext: { creatorProof: proof },
        }),
      ).resolves.toMatchObject({ ok: true });

      await registry.createIdentity("other@atHome");
      const otherAgent = await registry.registerAgent("other@atHome", {
        id: agent.agent.id,
        allowedCapabilities: ["email:draft"],
        deniedCapabilities: [],
      });
      const otherToken = await registry.issueCapabilityToken("other@atHome", {
        subject: otherAgent.agent.id,
        permissions: ["email:draft"],
        ttlSeconds: 3600,
      });
      const otherRequest = await registry.signRequest("other@atHome", {
        actor: otherAgent.agent.id,
        issuer: "other@atHome",
        capabilityToken: otherToken,
        method: "POST",
        path: "/emails/draft",
        body: { subject: "A1", message: "Proof-aware routing" },
      });
      await expect(
        registry.verifyRequest("other@atHome", otherRequest, {
          body: { subject: "A1", message: "Proof-aware routing" },
          policyHooks: [policy],
          policyContext: { creatorProof: proof },
        }),
      ).resolves.toMatchObject({ ok: false, code: "creator_proof_invalid" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
