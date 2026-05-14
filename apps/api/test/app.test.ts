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
import { API_RELEASE_VERSION } from "../src/release-version.js";

function mutationHeader(
  auth: ReturnType<typeof createMutationAuthorization>,
): Record<string, string> {
  return { "x-home-authorization": serializeMutationAuthorization(auth) };
}

async function createTempStore() {
  const dir = await mkdtemp(join(tmpdir(), "home-api-"));
  return {
    dir,
    store: new LocalJsonStore(dir),
  };
}

describe("api app", () => {
  it("creates and resolves an identity through HTTP", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const create = await app.inject({
        method: "POST",
        url: "/identities",
        payload: { id: "krav@atHome" },
      });

      expect(create.statusCode).toBe(201);

      const resolve = await app.inject({
        method: "POST",
        url: "/resolve",
        payload: { name: "krav@atHome" },
      });

      expect(resolve.statusCode).toBe(200);
      const body = resolve.json() as {
        ok: true;
        resolvedType: string;
        manifestSignatureValid: boolean;
      };
      expect(body.resolvedType).toBe("root");
      expect(body.manifestSignatureValid).toBe(true);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("keeps API release version consistent across status and OpenAPI", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const status = await app.inject({
        method: "GET",
        url: "/status",
      });
      expect(status.statusCode).toBe(200);
      const statusBody = status.json() as {
        ok: true;
        status: string;
        version: string;
      };
      expect(statusBody.ok).toBe(true);
      expect(statusBody.version).toBe(API_RELEASE_VERSION);

      const openapi = await app.inject({
        method: "GET",
        url: "/openapi.json",
      });
      expect(openapi.statusCode).toBe(200);
      const openapiBody = openapi.json() as {
        info?: { version?: string };
      };
      expect(openapiBody.info?.version).toBe(statusBody.version);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("namespace lifecycle", () => {
  it("reserves a namespace", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      const res = await app.inject({
        method: "POST",
        url: "/namespaces/reserve",
        payload: { id: "alice@atHome" },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json() as {
        ok: true;
        manifest: { id: string };
        rootKeyId: string;
      };
      expect(body.ok).toBe(true);
      expect(body.manifest.id).toBe("alice@atHome");
      expect(body.rootKeyId).toBeDefined();
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects duplicate namespace reservation", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);

    try {
      await app.inject({
        method: "POST",
        url: "/namespaces/reserve",
        payload: { id: "bob@atHome" },
      });

      const duplicate = await app.inject({
        method: "POST",
        url: "/namespaces/reserve",
        payload: { id: "bob@atHome" },
      });

      expect(duplicate.statusCode).toBe(409);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("suspends and restores a namespace", async () => {
    const { dir, store } = await createTempStore();
    const custody = createMemoryKeyCustodyProvider({
      allowPrivateKeyExport: true,
      recordStore: store,
    });
    const app = buildApp(store, { custody });
    const registry = new IdentityRegistry(store, custody);

    try {
      const { rootKey } = await registry.createIdentity("carol@atHome");

      const suspendBody = { reason: "abuse review" };
      const suspendAuth = createMutationAuthorization({
        issuer: "carol@atHome",
        signatureKeyId: rootKey.id,
        method: "POST",
        path: "/namespaces/carol@atHome/suspend",
        body: suspendBody,
        privateKey: rootKey.privateKey,
      });

      const suspend = await app.inject({
        method: "POST",
        url: "/namespaces/carol@atHome/suspend",
        headers: mutationHeader(suspendAuth),
        payload: suspendBody,
      });
      expect(suspend.statusCode).toBe(200);
      const suspendedManifest = (
        suspend.json() as { ok: true; manifest: { id: string } }
      ).manifest;
      expect(suspendedManifest.id).toBe("carol@atHome");

      const restoreBody = { reason: "review complete" };
      const restoreAuth = createMutationAuthorization({
        issuer: "carol@atHome",
        signatureKeyId: rootKey.id,
        method: "POST",
        path: "/namespaces/carol@atHome/restore",
        body: restoreBody,
        privateKey: rootKey.privateKey,
      });

      const restore = await app.inject({
        method: "POST",
        url: "/namespaces/carol@atHome/restore",
        headers: mutationHeader(restoreAuth),
        payload: restoreBody,
      });
      expect(restore.statusCode).toBe(200);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("transfers a namespace", async () => {
    const { dir, store } = await createTempStore();
    const custody = createMemoryKeyCustodyProvider({
      allowPrivateKeyExport: true,
      recordStore: store,
    });
    const app = buildApp(store, { custody });
    const registry = new IdentityRegistry(store, custody);

    try {
      const { rootKey } = await registry.createIdentity("dave@atHome");

      const transferBody = { reason: "ownership change" };
      const transferAuth = createMutationAuthorization({
        issuer: "dave@atHome",
        signatureKeyId: rootKey.id,
        method: "POST",
        path: "/namespaces/dave@atHome/transfer",
        body: transferBody,
        privateKey: rootKey.privateKey,
      });

      const res = await app.inject({
        method: "POST",
        url: "/namespaces/dave@atHome/transfer",
        headers: mutationHeader(transferAuth),
        payload: transferBody,
      });

      expect(res.statusCode).toBe(201);
      const body = res.json() as {
        ok: true;
        rootKeyId: string;
        rotated: { oldRootKeyId: string; newRootKeyId: string };
      };
      expect(body.ok).toBe(true);
      expect(body.rotated.oldRootKeyId).not.toBe(body.rotated.newRootKeyId);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("recovers a namespace", async () => {
    const { dir, store } = await createTempStore();
    const custody = createMemoryKeyCustodyProvider({
      allowPrivateKeyExport: true,
      recordStore: store,
    });
    const app = buildApp(store, { custody });
    const registry = new IdentityRegistry(store, custody);

    try {
      const { rootKey } = await registry.createIdentity("eve@atHome");

      const recoverBody = { reason: "lost root key" };
      const recoverAuth = createMutationAuthorization({
        issuer: "eve@atHome",
        signatureKeyId: rootKey.id,
        method: "POST",
        path: "/namespaces/eve@atHome/recover",
        body: recoverBody,
        privateKey: rootKey.privateKey,
      });

      const res = await app.inject({
        method: "POST",
        url: "/namespaces/eve@atHome/recover",
        headers: mutationHeader(recoverAuth),
        payload: recoverBody,
      });

      expect(res.statusCode).toBe(201);
      const body = res.json() as {
        ok: true;
        rootKeyId: string;
        rotated: { oldRootKeyId: string; newRootKeyId: string };
      };
      expect(body.ok).toBe(true);
      expect(body.rotated.oldRootKeyId).not.toBe(body.rotated.newRootKeyId);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects unauthenticated namespace lifecycle mutations", async () => {
    const { dir, store } = await createTempStore();
    const app = buildApp(store);
    const registry = new IdentityRegistry(store);

    try {
      await registry.createIdentity("frank@atHome");

      const res = await app.inject({
        method: "POST",
        url: "/namespaces/frank@atHome/suspend",
        payload: { reason: "no auth" },
      });
      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
