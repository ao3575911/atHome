import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  IdentityRegistry,
  LocalJsonStore,
  signCanonicalPayload,
} from "@home/protocol";
import { buildApp } from "../../../apps/api/src/app.js";
import * as sdk from "../src/index.js";

async function createTempStore() {
  const dir = await mkdtemp(join(tmpdir(), "home-sdk-hardening-"));
  return {
    dir,
    store: new LocalJsonStore(dir),
  };
}

describe("sdk hardening", () => {
  it("surfaces helper exports for revocation and signing", () => {
    const helperSurface = sdk as unknown as Record<string, unknown>;

    expect(helperSurface.createHomeClient).toBeTypeOf("function");
    expect(helperSurface.createSignedRequest).toBeTypeOf("function");
    expect(helperSurface.createRootMutationSigner).toBeTypeOf("function");
    expect(helperSurface.createExternalMutationSigner).toBeTypeOf("function");
    expect(helperSurface.resolveName).toBeTypeOf("function");
    expect(helperSurface.revokeAgent).toBeTypeOf("function");
    expect(helperSurface.revokeCapabilityToken).toBeTypeOf("function");
    expect(helperSurface.rotateRootKey).toBeTypeOf("function");
  });

  it("pins normalized openapi schema names for sdk generation", () => {
    expect(sdk.OPENAPI_SCHEMA_NAMES).toEqual([
      "AgentDefinition",
      "CapabilityToken",
      "ErrorResponse",
      "IdentityManifest",
      "PublicKey",
      "RecoveryMethod",
      "ServiceEndpoint",
      "SignedRequest",
      "VerificationOutcome",
      "VerifiedClaim",
    ]);
    expect(
      sdk.OPENAPI_SCHEMA_NAMES.some((name) => name.startsWith("def-")),
    ).toBe(false);
  });

  it("surfaces custody metadata on identity creation", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const address = await app.listen({ port: 0, host: "127.0.0.1" });
      const client = sdk.createHomeClient(address.replace(/\/$/u, ""));

      const created = await client.createIdentity("custody@home");
      expect(created.custody).toMatchObject({
        mode: "local-dev-server-generated",
        privateKeyExported: false,
      });
      expect(created.privateKey).toBeUndefined();
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("throws a structured api error for failed requests", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const url = await app.listen({ port: 0, host: "127.0.0.1" });
      const baseUrl = url.replace(/\/$/u, "");
      const liveClient = sdk.createHomeClient(baseUrl);

      await expect(liveClient.createIdentity("")).rejects.toMatchObject({
        code: "invalid_request",
        message: expect.any(String),
      });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("can authorize mutations with an async external signer", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("external@home");
      const address = await app.listen({ port: 0, host: "127.0.0.1" });
      const client = sdk.createHomeClient(address.replace(/\/$/u, ""));
      const seenDrafts: unknown[] = [];

      const signer = sdk.createExternalMutationSigner({
        identityId: "external@home",
        keyId: rootKey.id,
        nonce: () => "external-signer-nonce",
        async signDraft(draft) {
          seenDrafts.push(draft);
          return signCanonicalPayload(draft, rootKey.privateKey);
        },
      });

      const response = await client.addService(
        "external@home",
        {
          id: "agent@external",
          type: "agent",
          endpoint: "https://example.test/agent",
        },
        signer,
      );

      expect(response.ok).toBe(true);
      expect(seenDrafts).toHaveLength(1);
      expect(seenDrafts[0]).toMatchObject({
        issuer: "external@home",
        signatureKeyId: rootKey.id,
        method: "POST",
        path: "/identities/external%40home/services",
        nonce: "external-signer-nonce",
      });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("can rotate a root key without exporting new private key material", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("rotate@home");
      const address = await app.listen({ port: 0, host: "127.0.0.1" });
      const client = sdk.createHomeClient(address.replace(/\/$/u, ""));
      const signer = sdk.createRootMutationSigner({
        identityId: "rotate@home",
        keyId: rootKey.id,
        privateKey: rootKey.privateKey,
      });

      const rotation = await client.rotateRootKey("rotate@home", signer);

      expect(rotation.ok).toBe(true);
      expect(rotation.privateKey).toBeUndefined();
      expect(rotation.custody.privateKeyExported).toBe(false);
      expect(rotation.rotated.oldRootKeyId).toBe(rootKey.id);
      expect(rotation.rootKeyId).toBe(rotation.rotated.newRootKeyId);
      expect(rotation.manifest.signatureKeyId).toBe(rotation.rootKeyId);
      expect(
        rotation.manifest.publicKeys.find((key) => key.id === rootKey.id),
      ).toMatchObject({ status: "deprecated" });
      expect(
        rotation.manifest.publicKeys.find(
          (key) => key.id === rotation.rootKeyId,
        ),
      ).toMatchObject({ status: "active", purpose: "root" });

      await expect(
        client.addService(
          "rotate@home",
          {
            id: "agent@rotate",
            type: "agent",
            endpoint: "https://example.test/agent",
          },
          signer,
        ),
      ).rejects.toMatchObject({ code: "key_deprecated" });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("can revoke a capability token through the api client", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("alice@home");
      await registry.registerAgent("alice@home", {
        id: "assistant@alice",
        allowedCapabilities: ["profile:read", "email:draft"],
        deniedCapabilities: [],
      });

      const token = await registry.issueCapabilityToken("alice@home", {
        subject: "assistant@alice",
        permissions: ["email:draft"],
        ttlSeconds: 3600,
      });

      const address = await app.listen({ port: 0, host: "127.0.0.1" });
      const client = sdk.createHomeClient(address.replace(/\/$/u, ""));

      const signer = sdk.createRootMutationSigner({
        identityId: "alice@home",
        keyId: rootKey.id,
        privateKey: rootKey.privateKey,
      });

      const revoke = await client.revokeCapabilityToken(
        "alice@home",
        token.id,
        signer,
      );
      expect(revoke.ok).toBe(true);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
