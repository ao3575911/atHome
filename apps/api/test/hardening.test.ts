import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  IdentityRegistry,
  LocalJsonStore,
  createMutationAuthorization,
  createMemoryKeyCustodyProvider,
  serializeMutationAuthorization,
} from "@athome/protocol";
import { buildApp } from "../src/app.js";

async function createTempStore() {
  const dir = await mkdtemp(join(tmpdir(), "home-api-hardening-"));
  return {
    dir,
    store: new LocalJsonStore(dir),
  };
}

function mutationHeader(
  authorization: ReturnType<typeof createMutationAuthorization>,
): Record<string, string> {
  return {
    "x-home-authorization": serializeMutationAuthorization(authorization),
  };
}

function createSharedRegistry(store: LocalJsonStore) {
  const custody = createMemoryKeyCustodyProvider({
    allowPrivateKeyExport: true,
    recordStore: store,
  });
  return {
    app: buildApp(store, { custody }),
    custody,
    registry: new IdentityRegistry(store, custody),
  };
}

async function exportPrivateKey(input: {
  custody: ReturnType<typeof createMemoryKeyCustodyProvider>;
  identityId: string;
  keyId: string;
}): Promise<string> {
  return input.custody.exportPrivateKey({
    identityId: input.identityId,
    keyId: input.keyId,
  });
}

function collectSchemaRefs(value: unknown, refs: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectSchemaRefs(item, refs);
    }
    return refs;
  }

  if (!value || typeof value !== "object") {
    return refs;
  }

  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (key === "$ref" && typeof entry === "string") {
      refs.push(entry);
      continue;
    }

    collectSchemaRefs(entry, refs);
  }

  return refs;
}

function okResponseProperties(operation: unknown, status: string) {
  return (
    operation as {
      responses?: Record<
        string,
        {
          content?: {
            "application/json"?: {
              schema?: {
                properties?: Record<string, unknown>;
              };
            };
          };
        }
      >;
    }
  ).responses?.[status]?.content?.["application/json"]?.schema?.properties;
}

describe("api hardening", () => {
  it("omits private keys by default", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const response = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "krav@atHome" },
      });

      expect(response.statusCode).toBe(201);
      const body = response.json() as {
        ok: true;
        privateKey?: string;
        custody: {
          mode: string;
          privateKeyExported: boolean;
          guidance: string;
        };
      };
      expect(body.privateKey).toBeUndefined();
      expect(body.custody).toMatchObject({
        mode: "browser-held",
        privateKeyExported: false,
      });
      expect(body.custody.guidance).toContain(
        "Private key material was not returned",
      );
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("never exports private keys even when the legacy env flag is present", async () => {
    const { dir, store } = await createTempStore();
    const previousFlag = process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"];
    process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"] = "true";
    const app = buildApp(store);

    try {
      const response = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "demo@atHome" },
      });

      expect(response.statusCode).toBe(201);
      const body = response.json() as {
        ok: true;
        privateKey?: string;
        custody: {
          mode: string;
          privateKeyExported: boolean;
          guidance: string;
        };
      };
      expect(body.privateKey).toBeUndefined();
      expect(body.custody).toMatchObject({
        mode: "browser-held",
        privateKeyExported: false,
      });
      expect(body.custody.guidance).toContain("client-side");
    } finally {
      if (previousFlag === undefined) {
        delete process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"];
      } else {
        process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"] = previousFlag;
      }
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects duplicate identity creation with conflict", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const first = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "krav@atHome" },
      });
      expect(first.statusCode).toBe(201);

      const second = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "krav@atHome" },
      });
      expect(second.statusCode).toBe(409);
      expect(second.json()).toMatchObject({
        ok: false,
        error: {
          code: "identity_already_exists",
        },
      });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("blocks identity bootstrap in production", async () => {
    const { dir, store } = await createTempStore();
    const previousNodeEnv = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";

    try {
      const app = buildApp(store);
      const response = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "prod@atHome" },
      });

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({
        ok: false,
        error: {
          code: "key_custody_required",
        },
      });

      await app.close();
    } finally {
      if (previousNodeEnv === undefined) {
        delete process.env["NODE_ENV"];
      } else {
        process.env["NODE_ENV"] = previousNodeEnv;
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("blocks local-signing registry mutations in production", async () => {
    const { dir, store } = await createTempStore();
    const previousNodeEnv = process.env["NODE_ENV"];
    const { registry } = createSharedRegistry(store);
    await registry.createIdentity("prod-mutation@atHome");
    process.env["NODE_ENV"] = "production";

    try {
      const app = buildApp(store);
      const response = await app.inject({
        method: "POST",
        url: "/identities/prod-mutation@atHome/services",
        payload: {
          id: "agent@prod-mutation",
          type: "agent",
          endpoint: "https://example.test/agent",
        },
      });

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({
        ok: false,
        error: {
          code: "key_custody_required",
        },
      });

      await app.close();
    } finally {
      if (previousNodeEnv === undefined) {
        delete process.env["NODE_ENV"];
      } else {
        process.env["NODE_ENV"] = previousNodeEnv;
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rotates root keys without exporting private key material by default", async () => {
    const { dir, store } = await createTempStore();
    const { app, custody, registry } = createSharedRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("rotate-api@atHome");
      const privateKey = await exportPrivateKey({
        custody,
        identityId: "rotate-api@atHome",
        keyId: rootKey.id,
      });
      const path = "/identities/rotate-api%40atHome/keys/root/rotate";
      const response = await app.inject({
        method: "POST",
        url: path,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "rotate-api@atHome",
            signatureKeyId: rootKey.id,
            method: "POST",
            path,
            privateKey,
          }),
        ),
      });

      expect(response.statusCode).toBe(201);
      const body = response.json() as {
        ok: true;
        privateKey?: string;
        rootKeyId: string;
        rotated: { oldRootKeyId: string; newRootKeyId: string };
        custody: { privateKeyExported: boolean };
      };
      expect(body.privateKey).toBeUndefined();
      expect(body.custody.privateKeyExported).toBe(false);
      expect(body.rotated.oldRootKeyId).toBe(rootKey.id);
      expect(body.rotated.newRootKeyId).toBe(body.rootKeyId);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects unauthenticated registry mutations", async () => {
    const { dir, store } = await createTempStore();
    const { app, registry } = createSharedRegistry(store);

    try {
      await registry.createIdentity("krav@atHome");

      const response = await app.inject({
        method: "POST",
        url: "/identities/krav@atHome/services",
        payload: {
          id: "agent@krav",
          type: "agent",
          endpoint: "https://example.test/agent",
        },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        ok: false,
        error: {
          code: "mutation_unauthorized",
        },
      });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("returns standardized error responses for invalid requests", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const response = await app.inject({
        method: "POST",
        url: "/identities",
        payload: {},
      });

      expect(response.statusCode).toBe(400);
      const body = response.json() as {
        ok: false;
        error: {
          code: string;
          message: string;
          details: Record<string, unknown>;
        };
      };
      expect(body.error.code).toBe("invalid_request");
      expect(body.error.message).toContain("id");
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exposes OpenAPI JSON and Swagger UI routes", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const openapi = await app.inject({
        method: "GET",
        url: "/openapi.json",
      });

      expect(openapi.statusCode).toBe(200);
      const spec = openapi.json() as {
        openapi: string;
        info: { title: string };
        paths: Record<string, Record<string, unknown>>;
        components: {
          schemas: Record<string, unknown>;
          securitySchemes?: Record<string, unknown>;
        };
      };
      expect(spec.openapi.startsWith("3.")).toBe(true);
      expect(spec.info.title).toBe("atHome API");
      expect(spec.paths["/identities"]).toBeDefined();
      expect(spec.paths["/identities/{id}/keys/{keyId}/revoke"]).toBeDefined();
      expect(spec.paths["/registry/stream"]).toBeDefined();
      expect(spec.paths["/registry/freshness"]).toBeDefined();
      expect(spec.paths["/verify/witness"]).toBeDefined();
      expect(spec.paths["/openapi.json"]).toBeUndefined();
      expect(spec.components).toMatchObject({
        securitySchemes: {
          AtHomeMutationAuthorization: {
            type: "apiKey",
            in: "header",
            name: "x-home-authorization",
          },
        },
      });
      expect(spec.paths["/identities/{id}/agents"]?.post).toMatchObject({
        operationId: "registerAgent",
        security: [{ AtHomeMutationAuthorization: [] }],
      });
      expect(spec.paths["/verify/witness"]?.post).toMatchObject({
        operationId: "verifyWitnessReceipt",
      });
      const componentNames = Object.keys(spec.components.schemas).sort();
      expect(componentNames).toEqual(
        expect.arrayContaining([
          "AgentDefinition",
          "CapabilityToken",
          "ErrorResponse",
          "IdentityManifest",
          "PublicKey",
          "RecoveryMethod",
          "ServiceEndpoint",
          "SignedRequest",
          "VerifiedClaim",
          "VerificationOutcome",
        ]),
      );
      expect(componentNames.some((name) => name.startsWith("def-"))).toBe(
        false,
      );

      const refs = collectSchemaRefs(spec);
      expect(refs.some((ref) => ref.includes("/def-"))).toBe(false);
      for (const [operation, status] of [
        [spec.paths["/identities"]?.post, "201"],
        [spec.paths["/identities/{id}/agents"]?.post, "201"],
        [spec.paths["/identities/{id}/keys/root/rotate"]?.post, "201"],
      ] as const) {
        expect(okResponseProperties(operation, status)).not.toHaveProperty(
          "privateKey",
        );
      }

      const docs = await app.inject({
        method: "GET",
        url: "/docs",
      });

      expect(docs.statusCode).toBe(200);
      expect(docs.headers["content-type"]).toContain("text/html");
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("ignores the legacy demo export flag when building the app", async () => {
    const { dir, store } = await createTempStore();
    const previousFlag = process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"];
    process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"] = "true";

    try {
      // In non-production: the legacy env var is a no-op — buildApp never throws for it
      expect(() => buildApp(store)).not.toThrow();
    } finally {
      if (previousFlag === undefined) {
        delete process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"];
      } else {
        process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"] = previousFlag;
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses ATHOME_DEMO_PRIVATE_KEY_EXPORT in production", async () => {
    const { dir, store } = await createTempStore();
    const previousNodeEnv = process.env["NODE_ENV"];
    const previousExport = process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"];
    process.env["NODE_ENV"] = "production";
    process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"] = "true";

    try {
      expect(() => buildApp(store)).toThrow(
        /ATHOME_DEMO_PRIVATE_KEY_EXPORT cannot be enabled in production/i,
      );
    } finally {
      if (previousNodeEnv === undefined) {
        delete process.env["NODE_ENV"];
      } else {
        process.env["NODE_ENV"] = previousNodeEnv;
      }
      if (previousExport === undefined) {
        delete process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"];
      } else {
        process.env["ATHOME_DEMO_PRIVATE_KEY_EXPORT"] = previousExport;
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("omits agent private keys by default", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("agents@home");
      const path = "/identities/agents%40home/agents";
      const payload = {
        id: "assistant@agents",
        allowedCapabilities: ["profile:read"],
        deniedCapabilities: [],
      };
      const response = await app.inject({
        method: "POST",
        url: path,
        payload,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "agents@home",
            signatureKeyId: rootKey.id,
            method: "POST",
            path,
            body: payload,
            privateKey: rootKey.privateKey,
          }),
        ),
      });

      expect(response.statusCode).toBe(201);
      const body = response.json() as {
        privateKey?: string;
        publicKeyId: string;
        custody: { privateKeyExported: boolean };
      };
      expect(body.privateKey).toBeUndefined();
      expect(body.publicKeyId).toBeTypeOf("string");
      expect(body.custody.privateKeyExported).toBe(false);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exports agent private keys only when demo export is enabled outside production", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store, { demoPrivateKeyExport: true });
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("demo-agents@home");
      const path = "/identities/demo-agents%40home/agents";
      const payload = {
        id: "assistant@demo-agents",
        allowedCapabilities: ["profile:read"],
        deniedCapabilities: [],
      };
      const response = await app.inject({
        method: "POST",
        url: path,
        payload,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "demo-agents@home",
            signatureKeyId: rootKey.id,
            method: "POST",
            path,
            body: payload,
            privateKey: rootKey.privateKey,
          }),
        ),
      });

      expect(response.statusCode).toBe(201);
      const body = response.json() as {
        privateKey?: string;
        custody: { privateKeyExported: boolean };
      };
      expect(body.privateKey).toBeTypeOf("string");
      expect(body.custody.privateKeyExported).toBe(true);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exports rotated root private keys only when demo export is enabled outside production", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store, { demoPrivateKeyExport: true });
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("demo-rotate@home");
      const path = "/identities/demo-rotate%40home/keys/root/rotate";
      const response = await app.inject({
        method: "POST",
        url: path,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "demo-rotate@home",
            signatureKeyId: rootKey.id,
            method: "POST",
            path,
            privateKey: rootKey.privateKey,
          }),
        ),
      });

      expect(response.statusCode).toBe(201);
      const body = response.json() as {
        privateKey?: string;
        custody: { privateKeyExported: boolean };
      };
      expect(body.privateKey).toBeTypeOf("string");
      expect(body.custody.privateKeyExported).toBe(true);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("revokes a capability token and rejects future verification", async () => {
    const { dir, store } = await createTempStore();
    const { app, custody, registry } = createSharedRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("krav@atHome");
      const privateKey = await exportPrivateKey({
        custody,
        identityId: "krav@atHome",
        keyId: rootKey.id,
      });
      await registry.registerAgent("krav@atHome", {
        id: "foreman@krav",
        allowedCapabilities: ["profile:read", "email:draft"],
        deniedCapabilities: ["payment:send"],
      });

      const token = await registry.issueCapabilityToken("krav@atHome", {
        subject: "foreman@krav",
        permissions: ["email:draft"],
        ttlSeconds: 3600,
      });

      const revoke = await app.inject({
        method: "POST",
        url: `/identities/krav@atHome/capability-tokens/${encodeURIComponent(token.id)}/revoke`,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "krav@atHome",
            signatureKeyId: rootKey.id,
            method: "POST",
            path: `/identities/krav@atHome/capability-tokens/${encodeURIComponent(token.id)}/revoke`,
            privateKey,
          }),
        ),
      });

      expect(revoke.statusCode).toBe(200);

      const request = await registry.signRequest("krav@atHome", {
        actor: "foreman@krav",
        issuer: "krav@atHome",
        capabilityToken: token,
        method: "POST",
        path: "/emails/draft",
        body: { subject: "Hello" },
      });

      const verification = await app.inject({
        method: "POST",
        url: "/verify/request",
        payload: {
          request,
          body: { subject: "Hello" },
        },
      });

      expect(verification.statusCode).toBe(200);
      const body = verification.json() as {
        ok: true;
        verification: { ok: boolean; reason?: string };
      };
      expect(body.verification.ok).toBe(false);
      expect(body.verification.reason).toContain("revoked");
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("streams registry events with witness receipts", async () => {
    const { dir, store } = await createTempStore();
    const { app, custody, registry } = createSharedRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("stream@atHome");
      const privateKey = await exportPrivateKey({
        custody,
        identityId: "stream@atHome",
        keyId: rootKey.id,
      });
      await registry.registerAgent("stream@atHome", {
        id: "assistant@stream",
        allowedCapabilities: ["profile:read"],
        deniedCapabilities: [],
      });

      const response = await app.inject({
        method: "POST",
        url: "/identities/stream@atHome/agents/assistant%40stream/revoke",
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "stream@atHome",
            signatureKeyId: rootKey.id,
            method: "POST",
            path: "/identities/stream@atHome/agents/assistant%40stream/revoke",
            privateKey,
          }),
        ),
      });
      expect(response.statusCode).toBe(200);

      const stream = await app.inject({
        method: "GET",
        url: "/registry/stream?identityId=stream%40atHome",
      });

      expect(stream.statusCode).toBe(200);
      const body = stream.json() as {
        ok: true;
        events: Array<{ type: string; hash: string }>;
        witnessReceipts: Array<{ eventId: string; signature: string }>;
      };
      expect(body.events.map((event) => event.type)).toEqual(
        expect.arrayContaining(["identity.created", "agent.revoked"]),
      );
      expect(body.events.every((event) => event.hash.length > 0)).toBe(true);
      expect(body.witnessReceipts).toHaveLength(1);
      expect(body.witnessReceipts[0]?.signature).toBeTruthy();
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("returns registry freshness metadata", async () => {
    const { dir, store } = await createTempStore();
    const { app, registry } = createSharedRegistry(store);

    try {
      await registry.createIdentity("fresh@atHome");

      const response = await app.inject({
        method: "GET",
        url: "/registry/freshness?identityId=fresh%40atHome",
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({
        ok: true,
        freshness: {
          identityId: "fresh@atHome",
          eventCount: 1,
          witnessReceiptCount: 0,
        },
      });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("verifies stored witness receipts", async () => {
    const { dir, store } = await createTempStore();
    const { app, custody, registry } = createSharedRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("witness@atHome");
      const privateKey = await exportPrivateKey({
        custody,
        identityId: "witness@atHome",
        keyId: rootKey.id,
      });
      await registry.registerAgent("witness@atHome", {
        id: "assistant@witness",
        allowedCapabilities: ["profile:read"],
        deniedCapabilities: [],
      });
      const path =
        "/identities/witness@atHome/agents/assistant%40witness/revoke";
      const revoke = await app.inject({
        method: "POST",
        url: path,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "witness@atHome",
            signatureKeyId: rootKey.id,
            method: "POST",
            path,
            privateKey,
          }),
        ),
      });
      expect(revoke.statusCode).toBe(200);

      const events = await store.listEvents("witness@atHome");
      const receipts = await store.listWitnessReceipts("witness@atHome");
      const receipt = receipts[0];
      expect(receipt).toBeDefined();

      const verification = await app.inject({
        method: "POST",
        url: "/verify/witness",
        payload: {
          identityId: "witness@atHome",
          eventId: receipt?.eventId,
          receiptId: receipt?.receiptId,
        },
      });

      expect(verification.statusCode).toBe(200);
      expect(verification.json()).toMatchObject({
        ok: true,
        event: { id: events.at(-1)?.id },
        receipt: { receiptId: receipt?.receiptId },
        verification: { ok: true },
      });
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("enforces audience matching and missing audience checks", async () => {
    const { dir, store } = await createTempStore();
    const { app, registry } = createSharedRegistry(store);

    try {
      await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "alice@atHome" },
      });

      await registry.registerAgent("alice@atHome", {
        id: "assistant@alice",
        allowedCapabilities: ["profile:read", "email:draft"],
        deniedCapabilities: [],
      });

      const audienceToken = await registry.issueCapabilityToken(
        "alice@atHome",
        {
          subject: "assistant@alice",
          permissions: ["email:draft"],
          audience: "inbox@alice",
          ttlSeconds: 3600,
        },
      );

      const unrestrictedToken = await registry.issueCapabilityToken(
        "alice@atHome",
        {
          subject: "assistant@alice",
          permissions: ["email:draft"],
          ttlSeconds: 3600,
        },
      );

      const matching = await app.inject({
        method: "POST",
        url: "/verify/capability",
        payload: {
          token: audienceToken,
          permission: "email:draft",
          expectedAudience: "inbox@alice",
        },
      });
      expect(matching.statusCode).toBe(200);
      expect(
        (matching.json() as { ok: true; verification: { ok: boolean } })
          .verification.ok,
      ).toBe(true);

      const mismatched = await app.inject({
        method: "POST",
        url: "/verify/capability",
        payload: {
          token: audienceToken,
          permission: "email:draft",
          expectedAudience: "vault@alice",
        },
      });
      expect(mismatched.statusCode).toBe(200);
      expect(
        (
          mismatched.json() as {
            ok: true;
            verification: { ok: boolean; code?: string };
          }
        ).verification,
      ).toMatchObject({
        ok: false,
        code: "audience_mismatch",
      });

      const missing = await app.inject({
        method: "POST",
        url: "/verify/capability",
        payload: {
          token: unrestrictedToken,
          permission: "email:draft",
          expectedAudience: "inbox@alice",
        },
      });
      expect(missing.statusCode).toBe(200);
      expect(
        (
          missing.json() as {
            ok: true;
            verification: { ok: boolean; code?: string };
          }
        ).verification,
      ).toMatchObject({
        ok: false,
        code: "audience_required",
      });

      const unrestricted = await app.inject({
        method: "POST",
        url: "/verify/capability",
        payload: {
          token: unrestrictedToken,
          permission: "email:draft",
        },
      });
      expect(unrestricted.statusCode).toBe(200);
      expect(
        (unrestricted.json() as { ok: true; verification: { ok: boolean } })
          .verification.ok,
      ).toBe(true);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
