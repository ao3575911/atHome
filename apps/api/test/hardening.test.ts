import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  IdentityRegistry,
  LocalJsonStore,
  createMutationAuthorization,
  serializeMutationAuthorization,
} from "@home/protocol";
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

describe("api hardening", () => {
  it("omits private keys by default", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const response = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "krav@home" },
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
        mode: "local-dev-server-generated",
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

  it("exports private keys only when demo export is enabled", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store, { demoPrivateKeyExport: true });

    try {
      const response = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "demo@home" },
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
      expect(body.privateKey).toBeTypeOf("string");
      expect(body.custody).toMatchObject({
        mode: "local-dev-export",
        privateKeyExported: true,
      });
      expect(body.custody.guidance).toContain("local development only");
    } finally {
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
        payload: { id: "krav@home" },
      });
      expect(first.statusCode).toBe(201);

      const second = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "krav@home" },
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
        payload: { id: "prod@home" },
      });

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({
        ok: false,
        error: {
          code: "mutation_unauthorized",
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
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("rotate-api@home");
      const path = "/identities/rotate-api%40home/keys/root/rotate";
      const response = await app.inject({
        method: "POST",
        url: path,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "rotate-api@home",
            signatureKeyId: rootKey.id,
            method: "POST",
            path,
            privateKey: rootKey.privateKey,
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
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      await registry.createIdentity("krav@home");

      const response = await app.inject({
        method: "POST",
        url: "/identities/krav@home/services",
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
        paths: Record<string, Record<string, unknown>>;
        components: {
          schemas: Record<string, unknown>;
          securitySchemes?: Record<string, unknown>;
        };
      };
      expect(spec.openapi.startsWith("3.")).toBe(true);
      expect(spec.paths["/identities"]).toBeDefined();
      expect(spec.paths["/identities/{id}/keys/{keyId}/revoke"]).toBeDefined();
      expect(spec.paths["/openapi.json"]).toBeUndefined();
      expect(spec.components).toMatchObject({
        securitySchemes: {
          HomeMutationAuthorization: {
            type: "apiKey",
            in: "header",
            name: "x-home-authorization",
          },
        },
      });
      expect(spec.paths["/identities/{id}/agents"]?.post).toMatchObject({
        operationId: "registerAgent",
        security: [{ HomeMutationAuthorization: [] }],
      });
      const componentNames = Object.keys(spec.components.schemas).sort();
      expect(componentNames).toHaveLength(10);
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

  it("refuses demo private key export in production", async () => {
    const { dir, store } = await createTempStore();
    const previousNodeEnv = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";

    try {
      expect(() =>
        buildApp(store, {
          demoPrivateKeyExport: true,
        }),
      ).toThrow(/cannot be enabled in production/i);
    } finally {
      if (previousNodeEnv === undefined) {
        delete process.env["NODE_ENV"];
      } else {
        process.env["NODE_ENV"] = previousNodeEnv;
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("revokes a capability token and rejects future verification", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      const { rootKey } = await registry.createIdentity("krav@home");
      await registry.registerAgent("krav@home", {
        id: "foreman@krav",
        allowedCapabilities: ["profile:read", "email:draft"],
        deniedCapabilities: ["payment:send"],
      });

      const token = await registry.issueCapabilityToken("krav@home", {
        subject: "foreman@krav",
        permissions: ["email:draft"],
        ttlSeconds: 3600,
      });

      const revoke = await app.inject({
        method: "POST",
        url: `/identities/krav@home/capability-tokens/${encodeURIComponent(token.id)}/revoke`,
        headers: mutationHeader(
          createMutationAuthorization({
            issuer: "krav@home",
            signatureKeyId: rootKey.id,
            method: "POST",
            path: `/identities/krav@home/capability-tokens/${encodeURIComponent(token.id)}/revoke`,
            privateKey: rootKey.privateKey,
          }),
        ),
      });

      expect(revoke.statusCode).toBe(200);

      const request = await registry.signRequest("krav@home", {
        actor: "foreman@krav",
        issuer: "krav@home",
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

  it("enforces audience matching and missing audience checks", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "alice@home" },
      });

      await registry.registerAgent("alice@home", {
        id: "assistant@alice",
        allowedCapabilities: ["profile:read", "email:draft"],
        deniedCapabilities: [],
      });

      const audienceToken = await registry.issueCapabilityToken("alice@home", {
        subject: "assistant@alice",
        permissions: ["email:draft"],
        audience: "inbox@alice",
        ttlSeconds: 3600,
      });

      const unrestrictedToken = await registry.issueCapabilityToken(
        "alice@home",
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
