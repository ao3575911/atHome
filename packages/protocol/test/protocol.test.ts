import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  canPerform,
  IdentityRegistry,
  LocalJsonStore,
  canonicalize,
  createSignedRequest,
  generateEd25519KeyPair,
  hashBody,
  signCanonicalPayload,
  verifyCanonicalPayload,
  verifyIdentityManifest,
  verifySignedPayloadWithManifest,
  type IdentityManifest,
  type PublicKey,
} from "../src/index.js";

async function createTempRegistry(): Promise<{
  registry: IdentityRegistry;
  dir: string;
}> {
  const dir = await mkdtemp(join(tmpdir(), "home-protocol-"));
  return {
    dir,
    registry: new IdentityRegistry(new LocalJsonStore(dir)),
  };
}

describe("protocol primitives", () => {
  it("canonicalizes nested objects deterministically", () => {
    expect(canonicalize({ b: 1, a: { d: 4, c: 3 } })).toBe(
      '{"a":{"c":3,"d":4},"b":1}',
    );
  });

  it("signs and verifies payloads with ed25519", () => {
    const keys = generateEd25519KeyPair();
    const payload = { hello: "world" };
    const signature = signCanonicalPayload(payload, keys.privateKey);
    expect(verifyCanonicalPayload(payload, signature, keys.publicKey)).toBe(
      true,
    );
  });

  it("hashes request bodies consistently", () => {
    expect(hashBody({ a: 1, b: 2 })).toBe(hashBody({ b: 2, a: 1 }));
  });

  it("keeps canonical signing stable across field order and rejects mutations", () => {
    const keys = generateEd25519KeyPair();
    const draftA = { id: "demo", nested: { b: 2, a: 1 }, list: ["x", "y"] };
    const draftB = { nested: { a: 1, b: 2 }, list: ["x", "y"], id: "demo" };
    const signature = signCanonicalPayload(draftA, keys.privateKey);

    expect(verifyCanonicalPayload(draftB, signature, keys.publicKey)).toBe(
      true,
    );
    expect(
      verifyCanonicalPayload(
        { ...draftB, nested: { a: 9, b: 2 } },
        signature,
        keys.publicKey,
      ),
    ).toBe(false);
  });

  it("prefers explicit deny rules over allow rules", () => {
    const denied = canPerform({
      requestedPermission: "payment:send",
      tokenPermissions: ["payment:send"],
      tokenDenied: ["payment:send"],
      agentAllowed: ["payment:send"],
      agentDenied: [],
    });

    expect(denied.ok).toBe(false);
    expect(denied.code).toBe("permission_denied");
  });
});

describe("identity policy", () => {
  it("creates, resolves, authorizes, and verifies signed requests", async () => {
    const { registry, dir } = await createTempRegistry();

    try {
      await registry.createIdentity("krav@atHome");
      await registry.registerService("krav@atHome", {
        id: "agent@krav",
        type: "agent",
        endpoint: "https://example.test/agent",
      });
      const agent = await registry.registerAgent("krav@atHome", {
        id: "foreman@krav",
        allowedCapabilities: ["profile:read", "email:draft", "logs:analyze"],
        deniedCapabilities: ["payment:send", "vault:delete", "social:post"],
        endpoint: "https://example.test/foreman",
      });

      const token = await registry.issueCapabilityToken("krav@atHome", {
        subject: "foreman@krav",
        permissions: ["profile:read", "email:draft", "logs:analyze"],
        denied: ["payment:send", "vault:delete", "social:post"],
        ttlSeconds: 3600,
      });

      const request = await registry.signRequest("krav@atHome", {
        actor: "foreman@krav",
        issuer: "krav@atHome",
        capabilityToken: token,
        method: "POST",
        path: "/emails/draft",
        body: { subject: "Hello", message: "Draft this email." },
      });

      const success = await registry.verifyRequest("krav@atHome", request, {
        body: { subject: "Hello", message: "Draft this email." },
      });
      expect(success.ok).toBe(true);

      const deniedRequest = await registry.signRequest("krav@atHome", {
        actor: "foreman@krav",
        issuer: "krav@atHome",
        capabilityToken: token,
        method: "POST",
        path: "/payments/send",
        body: { amount: 25 },
      });

      const denied = await registry.verifyRequest(
        "krav@atHome",
        deniedRequest,
        {
          body: { amount: 25 },
        },
      );
      expect(denied.ok).toBe(false);
      expect(denied.code).toBe("permission_denied");

      const resolution = await registry.resolve("agent@krav");
      expect(resolution.manifestSignatureValid).toBe(true);
      expect(resolution.resolvedType).toBe("service");
      expect(resolution.publicKey?.purpose).toBe("root");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("enforces audience requirements and revocations", async () => {
    const { registry, dir } = await createTempRegistry();

    try {
      await registry.createIdentity("alice@atHome");
      const agent = await registry.registerAgent("alice@atHome", {
        id: "assistant@alice",
        allowedCapabilities: ["email:draft", "profile:read"],
        deniedCapabilities: ["payment:send", "vault:delete"],
      });

      const audienceToken = await registry.issueCapabilityToken(
        "alice@atHome",
        {
          subject: "assistant@alice",
          permissions: ["email:draft", "profile:read"],
          denied: ["payment:send"],
          audience: "inbox@alice",
          ttlSeconds: 3600,
        },
      );

      const inboxRequest = await registry.signRequest("alice@atHome", {
        actor: "assistant@alice",
        issuer: "alice@atHome",
        capabilityToken: audienceToken,
        method: "POST",
        path: "/inbox/messages",
        body: {
          subject: "Welcome",
          message: "Please route this message to Alice inbox.",
        },
      });

      const inboxVerification = await registry.verifyRequest(
        "alice@atHome",
        inboxRequest,
        {
          body: {
            subject: "Welcome",
            message: "Please route this message to Alice inbox.",
          },
          expectedAudience: "inbox@alice",
        },
      );
      expect(inboxVerification.ok).toBe(true);

      const vaultMismatch = await registry.verifyRequest(
        "alice@atHome",
        inboxRequest,
        {
          body: {
            subject: "Welcome",
            message: "Please route this message to Alice inbox.",
          },
          expectedAudience: "vault@alice",
        },
      );
      expect(vaultMismatch.ok).toBe(false);
      expect(vaultMismatch.code).toBe("audience_mismatch");

      const audienceFailure = await registry.verifyCapability(
        "alice@atHome",
        await registry.issueCapabilityToken("alice@atHome", {
          subject: "assistant@alice",
          permissions: ["email:draft"],
          ttlSeconds: 3600,
        }),
        "email:draft",
        { expectedAudience: "inbox@alice" },
      );
      expect(audienceFailure.ok).toBe(false);
      expect(audienceFailure.code).toBe("audience_required");

      const noAudienceToken = await registry.issueCapabilityToken(
        "alice@atHome",
        {
          subject: "assistant@alice",
          permissions: ["email:draft"],
          ttlSeconds: 3600,
        },
      );
      const unrestricted = await registry.verifyCapability(
        "alice@atHome",
        noAudienceToken,
        "email:draft",
      );
      expect(unrestricted.ok).toBe(true);

      const revokedToken = await registry.issueCapabilityToken("alice@atHome", {
        subject: "assistant@alice",
        permissions: ["email:draft"],
        audience: "inbox@alice",
        ttlSeconds: 3600,
      });
      await registry.revokeCapabilityToken("alice@atHome", revokedToken.id);
      const revokedTokenRequest = await registry.signRequest("alice@atHome", {
        actor: "assistant@alice",
        issuer: "alice@atHome",
        capabilityToken: revokedToken,
        method: "POST",
        path: "/inbox/messages",
        body: { subject: "Hello", message: "Revoked later" },
      });
      const revokedTokenVerification = await registry.verifyRequest(
        "alice@atHome",
        revokedTokenRequest,
        {
          body: { subject: "Hello", message: "Revoked later" },
          expectedAudience: "inbox@alice",
        },
      );
      expect(revokedTokenVerification.ok).toBe(false);
      expect(revokedTokenVerification.code).toBe("token_revoked");

      await registry.createIdentity("bob@atHome");
      await registry.registerAgent("bob@atHome", {
        id: "assistant@bob",
        allowedCapabilities: ["email:draft"],
        deniedCapabilities: [],
      });
      const bobToken = await registry.issueCapabilityToken("bob@atHome", {
        subject: "assistant@bob",
        permissions: ["email:draft"],
        audience: "inbox@bob",
        ttlSeconds: 3600,
      });
      const bobRequest = await registry.signRequest("bob@atHome", {
        actor: "assistant@bob",
        issuer: "bob@atHome",
        capabilityToken: bobToken,
        method: "POST",
        path: "/inbox/messages",
        body: { subject: "Hello", message: "Route this message to Bob inbox." },
      });
      await registry.revokeAgent("bob@atHome", "assistant@bob");
      const revokedAgentVerification = await registry.verifyRequest(
        "bob@atHome",
        bobRequest,
        {
          body: {
            subject: "Hello",
            message: "Route this message to Bob inbox.",
          },
          expectedAudience: "inbox@bob",
        },
      );
      expect(revokedAgentVerification.ok).toBe(false);
      expect(revokedAgentVerification.code).toBe("agent_revoked");

      await registry.createIdentity("carol@atHome");
      const carolAgent = await registry.registerAgent("carol@atHome", {
        id: "assistant@carol",
        allowedCapabilities: ["email:draft"],
        deniedCapabilities: [],
      });
      const carolToken = await registry.issueCapabilityToken("carol@atHome", {
        subject: "assistant@carol",
        permissions: ["email:draft"],
        audience: "inbox@carol",
        ttlSeconds: 3600,
      });
      const carolRequest = await registry.signRequest("carol@atHome", {
        actor: "assistant@carol",
        issuer: "carol@atHome",
        capabilityToken: carolToken,
        method: "POST",
        path: "/inbox/messages",
        body: {
          subject: "Hello",
          message: "Route this message to Carol inbox.",
        },
      });
      await registry.revokePublicKey(
        "carol@atHome",
        carolAgent.agent.publicKeyId,
      );
      const revokedKeyVerification = await registry.verifyRequest(
        "carol@atHome",
        carolRequest,
        {
          body: {
            subject: "Hello",
            message: "Route this message to Carol inbox.",
          },
          expectedAudience: "inbox@carol",
        },
      );
      expect(revokedKeyVerification.ok).toBe(false);
      expect(revokedKeyVerification.code).toBe("key_revoked");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("keeps deprecated keys valid for historical signatures but rejects revoked keys", async () => {
    const keys = generateEd25519KeyPair();
    const publicKey: PublicKey = {
      id: "root",
      type: "ed25519",
      publicKey: keys.publicKey,
      purpose: "root",
      status: "active",
      createdAt: new Date().toISOString(),
    };
    const manifest: IdentityManifest = {
      id: "demo@atHome",
      version: "1.0.0",
      publicKeys: [publicKey],
      services: [],
      agents: [],
      claims: [],
      updatedAt: new Date().toISOString(),
      signatureKeyId: "root",
      signature: "",
    };
    const draft = {
      id: manifest.id,
      version: manifest.version,
      publicKeys: manifest.publicKeys,
      services: manifest.services,
      agents: manifest.agents,
      claims: manifest.claims,
      updatedAt: manifest.updatedAt,
      signatureKeyId: manifest.signatureKeyId,
    };
    const signature = signCanonicalPayload(draft, keys.privateKey);
    const signedManifest = { ...manifest, signature };

    expect(verifyIdentityManifest(signedManifest).ok).toBe(true);
    expect(
      verifySignedPayloadWithManifest(
        draft,
        signature,
        {
          ...signedManifest,
          publicKeys: [{ ...publicKey, status: "deprecated" }],
        },
        "root",
        {
          allowDeprecated: false,
          invalidSignatureCode: "invalid_manifest_signature",
          missingKeyCode: "missing_root_key",
          revokedKeyCode: "invalid_manifest_signature",
          deprecatedKeyCode: "key_deprecated",
        },
      ).ok,
    ).toBe(false);
    expect(
      verifySignedPayloadWithManifest(
        draft,
        signature,
        {
          ...signedManifest,
          publicKeys: [{ ...publicKey, status: "deprecated" }],
        },
        "root",
        {
          allowDeprecated: true,
          invalidSignatureCode: "invalid_manifest_signature",
          missingKeyCode: "missing_root_key",
          revokedKeyCode: "invalid_manifest_signature",
          deprecatedKeyCode: "key_deprecated",
        },
      ).ok,
    ).toBe(true);
    expect(
      verifySignedPayloadWithManifest(
        draft,
        signature,
        {
          ...signedManifest,
          publicKeys: [{ ...publicKey, status: "revoked" }],
        },
        "root",
        {
          allowDeprecated: true,
          invalidSignatureCode: "invalid_manifest_signature",
          missingKeyCode: "missing_root_key",
          revokedKeyCode: "invalid_manifest_signature",
          deprecatedKeyCode: "key_deprecated",
        },
      ).ok,
    ).toBe(false);

    const mutatedManifest = {
      ...signedManifest,
      services: [
        {
          id: "agent@krav",
          type: "agent" as const,
          endpoint: "https://mutated.test",
          capabilities: [],
        },
      ],
    };
    expect(verifyIdentityManifest(mutatedManifest).ok).toBe(false);
  });

  it("records namespace reserve, suspend, restore, transfer, and recover lifecycle events", async () => {
    const { registry, dir } = await createTempRegistry();

    try {
      const reserved = await registry.reserveNamespace("ops@atHome");
      expect(
        reserved.manifest.claims.find(
          (entry) => entry.type === "namespace.status",
        )?.value,
      ).toBe("reserved");

      const created = await registry.getManifest("ops@atHome");
      expect(created?.id).toBe("ops@atHome");

      const suspended = await registry.suspendNamespace(
        "ops@atHome",
        "abuse investigation",
      );
      expect(
        suspended.claims.find((entry) => entry.type === "namespace.status")
          ?.value,
      ).toBe("suspended");

      const restored = await registry.restoreNamespace(
        "ops@atHome",
        "investigation cleared",
      );
      expect(
        restored.claims.find((entry) => entry.type === "namespace.status")
          ?.value,
      ).toBe("active");

      const transferred = await registry.transferNamespace(
        "ops@atHome",
        "custody migration",
      );
      expect(transferred.manifest.signatureKeyId).toBe(
        transferred.newRootKey.id,
      );

      const recovered = await registry.recoverNamespace(
        "ops@atHome",
        "root key loss recovery",
      );
      expect(recovered.manifest.signatureKeyId).toBe(recovered.newRootKey.id);

      const events = await registry.listEvents("ops@atHome");
      expect(events.map((event) => event.type)).toEqual(
        expect.arrayContaining([
          "namespace.reserved",
          "namespace.suspended",
          "namespace.restored",
          "namespace.transferred",
          "namespace.recovered",
          "identity.rotated",
        ]),
      );

      const transferEvent = [...events]
        .reverse()
        .find((event) => event.type === "namespace.transferred");
      expect(transferEvent?.details).toMatchObject({
        reason: "custody migration",
        oldRootKeyId: reserved.rootKey.id,
        newRootKeyId: transferred.newRootKey.id,
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rotates the active root key and preserves historical verification until revocation", async () => {
    const { registry, dir } = await createTempRegistry();

    try {
      await registry.createIdentity("rotate@atHome");
      const original = (await registry.getManifest(
        "rotate@atHome",
      )) as IdentityManifest;

      const rotation = await registry.rotateRootKey("rotate@atHome");
      const oldRoot = rotation.manifest.publicKeys.find(
        (entry) => entry.id === original.signatureKeyId,
      );
      const newRoot = rotation.manifest.publicKeys.find(
        (entry) => entry.id === rotation.newRootKey.id,
      );

      expect(rotation.manifest.signatureKeyId).toBe(rotation.newRootKey.id);
      expect(oldRoot?.status).toBe("deprecated");
      expect(newRoot?.status).toBe("active");
      expect(verifyIdentityManifest(rotation.manifest).ok).toBe(true);

      const draft = {
        id: original.id,
        version: original.version,
        publicKeys: original.publicKeys,
        services: original.services,
        agents: original.agents,
        claims: original.claims,
        recovery: original.recovery,
        updatedAt: original.updatedAt,
        expiresAt: original.expiresAt,
        signatureKeyId: original.signatureKeyId,
      };

      expect(
        verifySignedPayloadWithManifest(
          draft,
          original.signature,
          rotation.manifest,
          original.signatureKeyId,
          {
            allowDeprecated: true,
            invalidSignatureCode: "invalid_manifest_signature",
            missingKeyCode: "missing_root_key",
            revokedKeyCode: "invalid_manifest_signature",
            deprecatedKeyCode: "key_deprecated",
          },
        ).ok,
      ).toBe(true);

      await registry.revokePublicKey("rotate@atHome", original.signatureKeyId);
      const revokedManifest = (await registry.getManifest(
        "rotate@atHome",
      )) as IdentityManifest;

      expect(
        verifySignedPayloadWithManifest(
          draft,
          original.signature,
          revokedManifest,
          original.signatureKeyId,
          {
            allowDeprecated: true,
            invalidSignatureCode: "invalid_manifest_signature",
            missingKeyCode: "missing_root_key",
            revokedKeyCode: "invalid_manifest_signature",
            deprecatedKeyCode: "key_deprecated",
          },
        ).ok,
      ).toBe(false);
      expect(
        revokedManifest.publicKeys.find(
          (entry) => entry.id === original.signatureKeyId,
        )?.status,
      ).toBe("revoked");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
