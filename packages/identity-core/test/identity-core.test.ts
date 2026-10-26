import { describe, expect, it } from "vitest";
import {
  createEd25519Signer,
  generateEd25519IdentityKey,
  identityDocumentSchema,
  signIdentityDocument,
  verifyA1Signature,
  verifyIdentityDocument,
} from "../src/index.js";

describe("A1 identity core", () => {
  it("signs canonical payloads across supported public-key encodings", async () => {
    const { key, privateKey } = generateEd25519IdentityKey({
      id: "root",
      purpose: "root",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    const signer = createEd25519Signer({ keyId: key.id, privateKey });
    const signature = await signer.sign({ b: 2, a: { d: 4, c: 3 } });

    expect(
      verifyA1Signature({
        payload: { a: { c: 3, d: 4 }, b: 2 },
        signature,
        key,
      }),
    ).toEqual({ ok: true });

    const rawKey = {
      ...key,
      encoding: "raw-base64url" as const,
      publicKey: Buffer.from(key.publicKey, "base64")
        .subarray(-32)
        .toString("base64url"),
    };
    expect(
      verifyA1Signature({
        payload: { a: { c: 3, d: 4 }, b: 2 },
        signature,
        key: rawKey,
      }),
    ).toEqual({ ok: true });

    expect(
      verifyA1Signature({
        payload: { a: { c: 9, d: 4 }, b: 2 },
        signature,
        key,
      }),
    ).toMatchObject({ ok: false, code: "signature_invalid" });
  });

  it("signs identity documents and rejects revoked signing keys", async () => {
    const { key, privateKey } = generateEd25519IdentityKey({
      id: "root",
      purpose: "root",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    const document = await signIdentityDocument(
      {
        version: "a1",
        id: "alice@atHome",
        keys: [key],
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
      createEd25519Signer({ keyId: key.id, privateKey }),
    );

    expect(verifyIdentityDocument(document)).toEqual({ ok: true });
    expect(
      verifyIdentityDocument({
        ...document,
        keys: [{ ...key, status: "revoked" }],
      }),
    ).toMatchObject({ ok: false, code: "key_revoked" });
  });

  it("requires RFC 3339 timestamps", () => {
    expect(
      identityDocumentSchema.safeParse({
        version: "a1",
        id: "alice@atHome",
        keys: [
          {
            id: "root",
            algorithm: "Ed25519",
            encoding: "spki-der-base64",
            publicKey: "key",
            purpose: "root",
            status: "active",
            createdAt: "01/02/2026",
          },
        ],
        createdAt: "01/02/2026",
        updatedAt: "01/02/2026",
      }).success,
    ).toBe(false);
  });
});
