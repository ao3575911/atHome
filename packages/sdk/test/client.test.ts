import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  IdentityRegistry,
  LocalJsonStore,
  generateEd25519KeyPair,
  signCanonicalPayload,
} from "@athome/protocol";
import { buildApp } from "../../../apps/api/src/app.js";
import * as sdk from "../src/index.js";

async function createTempStore() {
  const dir = await mkdtemp(join(tmpdir(), "home-sdk-hardening-"));
  return {
    dir,
    store: new LocalJsonStore(dir),
  };
}

function createFetchFromApp(app: ReturnType<typeof buildApp>) {
  type InjectMethod =
    | "GET"
    | "POST"
    | "PUT"
    | "PATCH"
    | "DELETE"
    | "HEAD"
    | "OPTIONS";
  type InjectResponse = {
    body: string;
    statusCode: number;
    headers: Record<string, string>;
  };
  const inject = app.inject as unknown as (options: {
    method: InjectMethod;
    url: string;
    headers?: Record<string, string>;
    payload?: unknown;
  }) => Promise<InjectResponse>;

  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(
      typeof input === "string" || input instanceof URL
        ? input.toString()
        : input.url,
    );
    const method =
      init?.method ??
      (typeof input !== "string" && !(input instanceof URL)
        ? input.method
        : "GET");
    const response = await inject({
      method: method as InjectMethod,
      url: url.toString(),
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      payload: init?.body,
    });

    return new Response(response.body, {
      status: response.statusCode,
      headers: response.headers as HeadersInit,
    });
  };
}

describe("sdk hardening", () => {
  it("surfaces helper exports for revocation and signing", () => {
    const helperSurface = sdk as unknown as Record<string, unknown>;

    expect(helperSurface.createAtHomeClient).toBeTypeOf("function");
    expect(helperSurface.getReadiness).toBeTypeOf("function");
    expect(helperSurface.getStatus).toBeTypeOf("function");
    expect(helperSurface.createSignedRequest).toBeTypeOf("function");
    expect(helperSurface.createInMemoryMutationSigner).toBeTypeOf("function");
    expect(helperSurface.createExternalMutationSigner).toBeTypeOf("function");
    expect(helperSurface.createInMemoryRequestSigner).toBeTypeOf("function");
    expect(helperSurface.createExternalRequestSigner).toBeTypeOf("function");
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
      "RegistryCheckpoint",
      "RegistryEvent",
      "RegistryFreshness",
      "ServiceEndpoint",
      "SignedRequest",
      "VerificationOutcome",
      "VerifiedClaim",
      "WitnessReceipt",
    ]);
    expect(
      sdk.OPENAPI_SCHEMA_NAMES.some((name) => name.startsWith("def-")),
    ).toBe(false);
  });

  it("surfaces custody metadata on identity creation", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      await app.ready();
      const client = sdk.createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
      );
      const bootstrapKeys = generateEd25519KeyPair();
      const bootstrapSigner = sdk.createInMemoryMutationSigner({
        identityId: "custody@atHome",
        privateKey: bootstrapKeys.privateKey,
      });

      const created = await client.createIdentity(
        "custody@atHome",
        bootstrapSigner,
      );
      expect(created.custody).toMatchObject({
        mode: "browser-held",
        privateKeyExported: false,
      });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("throws a structured api error for failed requests", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      await app.ready();
      const liveClient = sdk.createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
      );
      const signer = sdk.createInMemoryMutationSigner({
        identityId: "invalid@atHome",
        privateKey: generateEd25519KeyPair().privateKey,
      });

      await expect(liveClient.createIdentity("", signer)).rejects.toMatchObject(
        {
          code: "invalid_request",
          message: expect.any(String),
        },
      );
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("wraps network failures in AtHomeApiError", async () => {
    const client = new sdk.AtHomeClient(
      "https://api.example.test",
      (async () => {
        throw new TypeError("connection refused");
      }) as typeof fetch,
    );

    await expect(client.getStatus()).rejects.toMatchObject({
      name: "AtHomeApiError",
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
    const client = new sdk.AtHomeClient("https://api.example.test", fetchImpl);

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
    await expect(failedEventsRequest).rejects.toBeInstanceOf(
      sdk.AtHomeApiError,
    );
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
    const client = new sdk.AtHomeClient("https://api.example.test", fetchImpl);

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
      await app.ready();
      const { rootKey } = await registry.createIdentity("external@atHome");
      const client = sdk.createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
      );
      const seenDrafts: unknown[] = [];

      const signer = sdk.createExternalMutationSigner({
        identityId: "external@atHome",
        keyId: rootKey.id,
        nonce: () => "external-signer-nonce",
        async signDraft(draft) {
          seenDrafts.push(draft);
          return signCanonicalPayload(draft, rootKey.privateKey);
        },
      });

      const response = await client.addService(
        "external@atHome",
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
        issuer: "external@atHome",
        signatureKeyId: rootKey.id,
        method: "POST",
        path: "/identities/external%40atHome/services",
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
      await app.ready();
      const { rootKey } = await registry.createIdentity("rotate@atHome");
      const client = sdk.createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
      );
      const signer = sdk.createInMemoryMutationSigner({
        identityId: "rotate@atHome",
        keyId: rootKey.id,
        privateKey: rootKey.privateKey,
      });

      const rotation = await client.rotateRootKey("rotate@atHome", signer);

      expect(rotation.ok).toBe(true);
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
          "rotate@atHome",
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
      await app.ready();
      const { rootKey } = await registry.createIdentity("alice@atHome");
      await registry.registerAgent("alice@atHome", {
        id: "assistant@alice",
        allowedCapabilities: ["profile:read", "email:draft"],
        deniedCapabilities: [],
      });

      const token = await registry.issueCapabilityToken("alice@atHome", {
        subject: "assistant@alice",
        permissions: ["email:draft"],
        ttlSeconds: 3600,
      });

      const client = sdk.createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
      );

      const signer = sdk.createInMemoryMutationSigner({
        identityId: "alice@atHome",
        keyId: rootKey.id,
        privateKey: rootKey.privateKey,
      });

      const revoke = await client.revokeCapabilityToken(
        "alice@atHome",
        token.id,
        signer,
      );
      expect(revoke.ok).toBe(true);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("can sign and verify a service request with an in-memory request signer", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      await app.ready();
      await registry.createIdentity("request@atHome");
      const agent = await registry.registerAgent("request@atHome", {
        id: "assistant@request",
        allowedCapabilities: ["email:draft"],
        deniedCapabilities: [],
      });
      const token = await registry.issueCapabilityToken("request@atHome", {
        subject: "assistant@request",
        permissions: ["email:draft"],
        audience: "agent@request",
        ttlSeconds: 3600,
      });
      const client = sdk.createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
      );
      const signer = sdk.createInMemoryRequestSigner({
        actor: agent.agent.id,
        issuer: "request@atHome",
        signatureKeyId: agent.agentKey.id,
        privateKey: agent.agentKey.privateKey,
      });
      const body = { subject: "Hello", message: "Draft this note." };

      const signed = await signer.signRequest({
        capabilityToken: token,
        method: "POST",
        path: "/emails/draft",
        body,
        expectedAudience: "agent@request",
      });
      const verification = await client.verifyRequest(
        signed,
        body,
        "agent@request",
      );

      expect(agent.agentKey.privateKey).toBeTypeOf("string");
      expect(signed).toMatchObject({
        actor: "assistant@request",
        issuer: "request@atHome",
        signatureKeyId: "assistant@request#agent",
        method: "POST",
        path: "/emails/draft",
      });
      expect(verification.verification).toMatchObject({ ok: true });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("can authorize service requests with an async external request signer", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      await app.ready();
      await registry.createIdentity("external-request@atHome");
      const agent = await registry.registerAgent("external-request@atHome", {
        id: "assistant@external-request",
        allowedCapabilities: ["email:draft"],
        deniedCapabilities: [],
      });
      const token = await registry.issueCapabilityToken(
        "external-request@atHome",
        {
          subject: "assistant@external-request",
          permissions: ["email:draft"],
          audience: "agent@external-request",
          ttlSeconds: 3600,
        },
      );
      const client = sdk.createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
      );
      const seenDrafts: unknown[] = [];
      const signer = sdk.createExternalRequestSigner({
        actor: agent.agent.id,
        issuer: "external-request@atHome",
        signatureKeyId: agent.agentKey.id,
        nonce: () => "external-request-nonce",
        async signDraft(draft) {
          seenDrafts.push(draft);
          return signCanonicalPayload(draft, agent.agentKey.privateKey);
        },
      });
      const body = { subject: "Hello", message: "Draft this note." };

      const signed = await signer.signRequest({
        capabilityToken: token,
        method: "POST",
        path: "/emails/draft",
        body,
      });
      const verification = await client.verifyRequest(
        signed,
        body,
        "agent@external-request",
      );

      expect(seenDrafts).toHaveLength(1);
      expect(seenDrafts[0]).toMatchObject({
        actor: "assistant@external-request",
        issuer: "external-request@atHome",
        signatureKeyId: "assistant@external-request#agent",
        method: "POST",
        path: "/emails/draft",
        nonce: "external-request-nonce",
      });
      expect(verification.verification).toMatchObject({ ok: true });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
