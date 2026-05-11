import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { IdentityRegistry, LocalJsonStore } from "@home/protocol";
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
    expect(helperSurface.resolveName).toBeTypeOf("function");
    expect(helperSurface.revokeAgent).toBeTypeOf("function");
    expect(helperSurface.revokeCapabilityToken).toBeTypeOf("function");
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
