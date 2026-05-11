import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import { canonicalize } from "./canonical.js";

export function generateEd25519KeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  return {
    publicKey: publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64"),
    privateKey: privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64"),
  };
}

export function importPublicKey(publicKey: string) {
  return createPublicKey({
    key: Buffer.from(publicKey, "base64"),
    format: "der",
    type: "spki",
  });
}

export function importPrivateKey(privateKey: string) {
  return createPrivateKey({
    key: Buffer.from(privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
}

export function signCanonicalPayload(
  payload: unknown,
  privateKey: string,
): string {
  const message = Buffer.from(canonicalize(payload));
  return sign(null, message, importPrivateKey(privateKey)).toString("base64");
}

export function verifyCanonicalPayload(
  payload: unknown,
  signature: string,
  publicKey: string,
): boolean {
  try {
    const message = Buffer.from(canonicalize(payload));
    return verify(
      null,
      message,
      importPublicKey(publicKey),
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function randomNonce(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}
