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
    expect(helperSurface.getReadiness).toBeTypeOf("function");
    expect(helperSurface.getStatus).toBeTypeOf("function");
    expect(helperSurface.createSignedRequest).toBeTypeOf("function");
    expect(helperSurface.createRootMutationSigner).toBeTypeOf("function");
    expect(helperSurface.createExternalMutationSigner).toBeTypeOf("function");
    expect(helperSurface.resolveName).toBeTypeOf("function");
    expect(helperSurface.listIdentityEvents).toBeTypeOf("function");
    expect(helperSurface.listWitnessReceipts).toBeTypeOf("function");
    expect(helperSurface.getRevocationState).toBeTypeOf("function");
    expect(helperSurface.listAuditEvents).toBeTypeOf("function");
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

  it("wraps network failures in HomeApiError", async () => {
    const client = new sdk.HomeClient("https://api.example.test", (async () => {
      throw new TypeError("connection refused");
    }) as typeof fetch);

    await expect(client.getStatus()).rejects.toMatchObject({
      name: "HomeApiError",
      code: "network_error",
      message: "connection refused",
    });
  });

  it("calls platform status and audit endpoints with structured failures", async () => {
    const calls: string[] = [];
    const fetchImpl = (async (input) => {
      calls.push(String(input));
      const path = new URL(String(input)).pathname;

      if (path === "/health") {
        return new Response(JSON.stringify({ ok: true }));
      }

      if (path === "/status") {
        return new Response(
          JSON.stringify({
            ok: true,
            status: "healthy",
            services: [{ name: "api", status: "healthy" }],
          }),
        );
      }

      if (path === "/audit/events") {
        return new Response(
          JSON.stringify({
            ok: true,
            events: [
              {
                id: "audit-1",
                identityId: "alice@home",
                type: "identity.created",
                subjectId: "alice@home",
                timestamp: "2026-01-01T00:00:00.000Z",
                signerKeyId: "root",
                previousHash: "genesis",
                payloadHash: "payload-hash",
                signature: "signature",
              },
            ],
          }),
        );
      }

      return new Response(
        JSON.stringify({
          ok: false,
          error: {
            code: "status_unavailable",
            message: "Status unavailable",
            details: { path },
          },
        }),
        { status: 503 },
      );
    }) as typeof fetch;
    const client = new sdk.HomeClient("https://api.example.test", fetchImpl);

    await expect(client.getReadiness()).resolves.toEqual({ ok: true });
    await expect(sdk.getStatus(client)).resolves.toMatchObject({
      ok: true,
      status: "healthy",
    });
    await expect(sdk.listAuditEvents(client)).resolves.toMatchObject({
      ok: true,
      events: [{ id: "audit-1" }],
    });
    const failedEventsRequest = client.listIdentityEvents("missing@home");
    await expect(failedEventsRequest).rejects.toBeInstanceOf(sdk.HomeApiError);
    await expect(failedEventsRequest).rejects.toMatchObject({
      code: "status_unavailable",
      statusCode: 503,
      details: { path: "/identities/missing%40home/events" },
    });
    expect(calls).toEqual([
      "https://api.example.test/health",
      "https://api.example.test/status",
      "https://api.example.test/audit/events",
      "https://api.example.test/identities/missing%40home/events",
    ]);
  });

  it("calls identity event, witness, and revocation-state endpoints", async () => {
    const calls: string[] = [];
    const fetchImpl = (async (input) => {
      calls.push(String(input));
      const path = new URL(String(input)).pathname;

      if (path === "/identities/alice%40home/events") {
        return new Response(
          JSON.stringify({
            ok: true,
            events: [
              {
                id: "event-1",
                identityId: "alice@home",
                type: "agent.revoked",
                subjectId: "agent@alice",
                timestamp: "2026-01-01T00:00:00.000Z",
                signerKeyId: "root",
                previousHash: "previous-hash",
                payloadHash: "payload-hash",
                hash: "event-hash",
                signature: "signature",
              },
            ],
          }),
        );
      }

      if (path === "/identities/alice%40home/witness-receipts") {
        return new Response(
          JSON.stringify({
            ok: true,
            receipts: [
              {
                receiptId: "receipt-1",
                identityId: "alice@home",
                eventId: "event-1",
                eventHash: "event-hash",
                kind: "agent",
                subjectId: "agent@alice",
                revokedAt: "2026-01-01T00:00:00.000Z",
                payloadHash: "payload-hash",
                logIndex: 0,
                witnessKeyId: "witness",
                signature: "signature",
              },
            ],
          }),
        );
      }

      if (path === "/identities/alice%40home/revocation-state") {
        return new Response(
          JSON.stringify({
            ok: true,
            revocationState: {
              id: "alice@home",
              revokedAgents: {
                "agent@alice": {
                  revokedAt: "2026-01-01T00:00:00.000Z",
                },
              },
              revokedCapabilityTokens: {},
              revokedPublicKeys: {},
              updatedAt: "2026-01-01T00:00:00.000Z",
            },
          }),
        );
      }

      return new Response("not found", { status: 404 });
    }) as typeof fetch;
    const client = new sdk.HomeClient("https://api.example.test", fetchImpl);

    await expect(
      sdk.listIdentityEvents(client, "alice@home"),
    ).resolves.toMatchObject({
      ok: true,
      events: [{ id: "event-1", type: "agent.revoked" }],
    });
    await expect(
      sdk.listWitnessReceipts(client, "alice@home"),
    ).resolves.toMatchObject({
      ok: true,
      receipts: [{ receiptId: "receipt-1", eventId: "event-1" }],
    });
    await expect(
      sdk.getRevocationState(client, "alice@home"),
    ).resolves.toMatchObject({
      ok: true,
      revocationState: {
        id: "alice@home",
        revokedAgents: {
          "agent@alice": {
            revokedAt: "2026-01-01T00:00:00.000Z",
          },
        },
      },
    });
    expect(calls).toEqual([
      "https://api.example.test/identities/alice%40home/events",
      "https://api.example.test/identities/alice%40home/witness-receipts",
      "https://api.example.test/identities/alice%40home/revocation-state",
    ]);
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
