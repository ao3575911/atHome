import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  IdentityRegistry,
  LocalJsonStore,
  SQLiteRegistryBackend,
  type RegistryBackend,
} from "../src/index.js";

async function setup(backend: RegistryBackend) {
  const registry = new IdentityRegistry(backend);
  await registry.createIdentity("krav@atHome");
  await registry.registerAgent("krav@atHome", {
    id: "foreman@krav",
    allowedCapabilities: ["email:draft"],
    deniedCapabilities: [],
    endpoint: "https://example.test/foreman",
  });
  const token = await registry.issueCapabilityToken("krav@atHome", {
    subject: "foreman@krav",
    permissions: ["email:draft"],
  });
  const sign = () =>
    registry.signRequest("krav@atHome", {
      actor: "foreman@krav",
      issuer: "krav@atHome",
      capabilityToken: token,
      method: "POST",
      path: "/emails/draft",
      body: { s: "hi" },
    });
  return { registry, sign };
}

describe.each([
  [
    "SQLite",
    async () => ({ backend: new SQLiteRegistryBackend(":memory:"), dir: null }),
  ],
  [
    "LocalJsonStore",
    async () => {
      const dir = await mkdtemp(join(tmpdir(), "replay-"));
      return { backend: new LocalJsonStore(dir), dir };
    },
  ],
] as const)("replay protection under concurrency (%s)", (_name, make) => {
  it("accepts a signed request exactly once when verified in parallel", async () => {
    const { backend, dir } = await make();
    try {
      const { registry, sign } = await setup(backend);
      const request = await sign();
      const results = await Promise.all(
        Array.from({ length: 25 }, () =>
          registry.verifyRequest("krav@atHome", request, { body: { s: "hi" } }),
        ),
      );
      expect(results.filter((r) => r.ok)).toHaveLength(1);
      expect(results.filter((r) => r.code === "nonce_replayed")).toHaveLength(
        24,
      );
    } finally {
      if (dir) await rm(dir, { recursive: true, force: true });
    }
  });

  it("records every nonce when distinct requests are verified in parallel", async () => {
    const { backend, dir } = await make();
    try {
      const { registry, sign } = await setup(backend);
      const requests = await Promise.all(Array.from({ length: 50 }, sign));
      const results = await Promise.all(
        requests.map((r) =>
          registry.verifyRequest("krav@atHome", r, { body: { s: "hi" } }),
        ),
      );
      expect(results.every((r) => r.ok)).toBe(true);
      const again = await Promise.all(
        requests.map((r) =>
          registry.verifyRequest("krav@atHome", r, { body: { s: "hi" } }),
        ),
      );
      expect(again.every((r) => r.code === "nonce_replayed")).toBe(true);
    } finally {
      if (dir) await rm(dir, { recursive: true, force: true });
    }
  });
});
