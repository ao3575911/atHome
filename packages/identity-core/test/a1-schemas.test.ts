import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

async function loadSchema(name: string) {
  const path = fileURLToPath(
    new URL(`../../../schemas/${name}.schema.json`, import.meta.url),
  );
  return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
}

describe("A1 provisional schemas", () => {
  it("publish versioned, strict identity, attestation, and grant contracts", async () => {
    const [identity, attestation, grant] = await Promise.all([
      loadSchema("identity"),
      loadSchema("attestation"),
      loadSchema("capability-grant"),
    ]);

    for (const schema of [identity, attestation, grant]) {
      expect(schema.$schema).toBe(
        "https://json-schema.org/draft/2020-12/schema",
      );
      expect(schema.additionalProperties).toBe(false);
      expect(schema.properties).toMatchObject({
        version: { const: "a1" },
      });
    }

    expect(attestation.required).toEqual(
      expect.arrayContaining([
        "issuer",
        "subject",
        "claims",
        "issuedAt",
        "signature",
      ]),
    );
    expect(grant.required).toEqual(
      expect.arrayContaining(["permissions", "expiresAt", "signature"]),
    );
    expect(identity.properties).toMatchObject({
      signature: { $ref: "#/$defs/signature" },
    });
  });
});
