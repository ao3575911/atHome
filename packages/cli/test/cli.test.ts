import { describe, expect, it } from "vitest";
import {
  createEd25519Signer,
  generateEd25519IdentityKey,
} from "@athome/identity-core";
import {
  createCreatorProofDraft,
  signCreatorProof,
} from "@athome/creator-proof";
import { runCli } from "../src/index.js";

describe("A1 CLI", () => {
  it("creates a public identity document without handling private keys", async () => {
    const output: string[] = [];
    const { key } = generateEd25519IdentityKey({
      id: "root",
      purpose: "root",
    });
    const exitCode = await runCli(
      [
        "identity",
        "init",
        "alice@atHome",
        "--public-key",
        key.publicKey,
        "--json",
      ],
      {
        stdout: (message) => output.push(message),
        stderr: () => undefined,
        now: () => new Date("2026-01-01T00:00:00.000Z"),
        color: true,
      },
    );

    expect(exitCode).toBe(0);
    expect(output.join("")).toContain('"id": "alice@atHome"');
    expect(output.join("")).not.toContain("privateKey");
  });

  it("rejects a public key that cannot be used for Ed25519 verification", async () => {
    const errors: string[] = [];
    const exitCode = await runCli(
      ["identity", "init", "alice@atHome", "--public-key", "not-base64"],
      {
        stdout: () => undefined,
        stderr: (message) => errors.push(message),
        color: true,
      },
    );

    expect(exitCode).toBe(2);
    expect(errors.join("")).toContain("Ed25519 SPKI DER");
  });

  it("returns useful colored errors for missing verification trust anchors", async () => {
    const errors: string[] = [];
    const exitCode = await runCli(["proof", "verify", "proof.json"], {
      stdout: () => undefined,
      stderr: (message) => errors.push(message),
      readFile: async () => "{}",
      color: true,
    });

    expect(exitCode).toBe(2);
    expect(errors.join("")).toContain("\u001b[31merror:");
  });

  it("accepts opaque identifiers in structured trust anchors", async () => {
    const { key, privateKey } = generateEd25519IdentityKey({
      id: "urn:athome:root",
      purpose: "root",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    const proof = await signCreatorProof(
      createCreatorProofDraft({
        version: "a1",
        id: "proof",
        issuer: "did:example:alice",
        subject: "agent",
        claims: [{ type: "creator.control", value: true }],
        issuedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-02T00:00:00.000Z",
      }),
      createEd25519Signer({ keyId: key.id, privateKey }),
    );
    const exitCode = await runCli(
      [
        "proof",
        "verify",
        "proof.json",
        "--trust-anchor",
        JSON.stringify({
          issuer: "did:example:alice",
          keyId: "urn:athome:root",
          publicKey: key.publicKey,
        }),
      ],
      {
        stdout: () => undefined,
        stderr: () => undefined,
        readFile: async () => JSON.stringify(proof),
        now: () => new Date("2026-01-01T12:00:00.000Z"),
      },
    );

    expect(exitCode).toBe(0);
  });
});
