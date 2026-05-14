import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LocalJsonStore } from "@athome/protocol";
import { buildApp } from "../src/app.js";

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
      expect(statusBody.version).toBe("0.3.0-alpha2");

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
