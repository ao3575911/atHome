import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  IdentityRegistry,
  LocalJsonStore,
  createMemoryKeyCustodyProvider,
} from "@ao3575911/protocol";
import {
  createAtHomeClient,
  createInMemoryMutationSigner,
} from "@ao3575911/sdk";
import { buildApp } from "../src/app.js";

function createFetchFromApp(app: ReturnType<typeof buildApp>) {
  type InjectMethod =
    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
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

describe("mesh capability offers", () => {
  it("publishes, authorizes, and retires an offer", async () => {
    const dir = await mkdtemp(join(tmpdir(), "home-mco-"));
    const store = new LocalJsonStore(dir);
    const custody = createMemoryKeyCustodyProvider({
      allowPrivateKeyExport: true,
      recordStore: store,
    });
    const app = buildApp(store, { custody });
    const registry = new IdentityRegistry(store, custody);

    try {
      await app.ready();
      const openapi = await app.inject({ method: "GET", url: "/openapi.json" });
      const spec = openapi.json() as {
        paths: Record<string, Record<string, { operationId?: string }>>;
      };
      expect(spec.paths["/identities/{id}/mco"]?.post?.operationId).toBe(
        "publishMcoOffer",
      );
      expect(
        spec.paths["/identities/{id}/mco/authorize"]?.post?.operationId,
      ).toBe("authorizeMcoCall");

      const { rootKey } = await registry.createIdentity("krav@atHome");
      await registry.registerService("krav@atHome", {
        id: "inbox",
        type: "inbox",
        endpoint: "https://inbox.example/hook",
      });
      await registry.registerService("krav@atHome", {
        id: "pay",
        type: "pay",
        endpoint: "https://pay.example/hook",
      });

      const unsigned = await app.inject({
        method: "POST",
        url: "/identities/krav@atHome/mco",
        payload: {
          serviceId: "inbox",
          calls: [
            {
              id: "draft-message",
              method: "POST",
              path: "/inbox/messages",
              permission: "email:draft",
            },
          ],
        },
      });
      expect(unsigned.statusCode).toBe(401);

      const client = createAtHomeClient(
        "http://at-home.test",
        createFetchFromApp(app),
        createInMemoryMutationSigner({
          identityId: "krav@atHome",
          keyId: rootKey.id,
          privateKey: rootKey.privateKey,
        }),
      );

      const published = await client.publishMcoOffer("krav@atHome", {
        serviceId: "inbox",
        ttlSeconds: 3600,
        calls: [
          {
            id: "draft-message",
            method: "POST",
            path: "/inbox/messages",
            permission: "email:draft",
            delegatesTo: ["pay"],
          },
        ],
      });
      expect(published.offer.serviceId).toBe("inbox");

      const mesh = await client.readMcoMesh("krav@atHome");
      expect(mesh.mesh.edges).toEqual([
        {
          fromServiceId: "inbox",
          callId: "draft-message",
          toServiceId: "pay",
          permission: "email:draft",
        },
      ]);

      const allowed = await client.authorizeMcoCall("krav@atHome", {
        serviceId: "inbox",
        method: "POST",
        path: "/inbox/messages",
        permission: "email:draft",
        delegateServiceId: "pay",
      });
      expect(allowed.verification.ok).toBe(true);

      const denied = await client.authorizeMcoCall("krav@atHome", {
        serviceId: "inbox",
        method: "POST",
        path: "/inbox/messages",
        permission: "email:draft",
        delegateServiceId: "vault",
      });
      expect(denied.verification.ok).toBe(false);
      expect(denied.verification.code).toBe("mco_delegation_not_offered");

      const stream = await app.inject({
        method: "GET",
        url: "/registry/stream?identityId=krav@atHome",
      });
      expect(stream.statusCode).toBe(200);

      const retired = await client.retireMcoOffer("krav@atHome", "inbox");
      expect(
        retired.manifest.claims.some((claim) => claim.type === "mco.offer"),
      ).toBe(false);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
