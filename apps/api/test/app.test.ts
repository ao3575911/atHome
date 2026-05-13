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
});
