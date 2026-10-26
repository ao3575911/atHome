import { describe, expect, it } from "vitest";
import {
  createEd25519Signer,
  canonicalizeA1,
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

    expect(verifyIdentityDocument({ document, trustedKeys: [key] })).toEqual({
      ok: true,
    });
    expect(
      verifyIdentityDocument({
        document: {
          ...document,
          keys: [{ ...key, status: "revoked" }],
        },
        trustedKeys: [key],
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
            createdAt: "2026-02-30T00:00:00Z",
          },
        ],
        createdAt: "2026-02-30T00:00:00Z",
        updatedAt: "2026-02-30T00:00:00Z",
      }).success,
    ).toBe(false);
  });

  it("covers __proto__ properties in canonical payloads", () => {
    expect(canonicalizeA1(JSON.parse('{"__proto__":{"admin":true}}'))).toBe(
      '{"__proto__":{"admin":true}}',
    );
  });

  it("rejects expired keys and identity documents", async () => {
    const { key, privateKey } = generateEd25519IdentityKey({
      id: "root",
      purpose: "root",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    const signer = createEd25519Signer({ keyId: key.id, privateKey });
    const signature = await signer.sign({ payload: true });
    const expiredKey = { ...key, expiresAt: "2026-01-02T00:00:00.000Z" };
    expect(
      verifyA1Signature({
        payload: { payload: true },
        signature,
        key: expiredKey,
        now: new Date("2026-01-03T00:00:00.000Z"),
      }),
    ).toMatchObject({ ok: false, code: "key_expired" });

    const document = await signIdentityDocument(
      {
        version: "a1",
        id: "alice@atHome",
        keys: [key],
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-02T00:00:00.000Z",
      },
      signer,
    );
    expect(
      verifyIdentityDocument({
        document,
        trustedKeys: [key],
        now: new Date("2026-01-03T00:00:00.000Z"),
      }),
    ).toMatchObject({ ok: false, code: "document_expired" });
  });

  it("requires a trusted, unique signing key", async () => {
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
    expect(verifyIdentityDocument({ document, trustedKeys: [] })).toMatchObject(
      { ok: false, code: "untrusted_key" },
    );
    expect(
      identityDocumentSchema.safeParse({
        ...document,
        keys: [key, key],
      }).success,
    ).toBe(false);
  });
});
