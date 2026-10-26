import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { canonicalizeA1 } from "./canonical.js";
import {
  identityDocumentSchema,
  identityKeySchema,
  signatureEnvelopeSchema,
  signedIdentityDocumentSchema,
} from "./schemas.js";
import {
  A1_ENVELOPE_VERSION,
  ED25519_ALGORITHM,
  type IdentityCoreVerificationOutcome,
  type IdentityDocument,
  type IdentityKeyMaterial,
  type IdentitySigner,
  type SignatureEnvelope,
  type SignedIdentityDocument,
} from "./types.js";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function failure(
  code: NonNullable<IdentityCoreVerificationOutcome["code"]>,
  reason: string,
): IdentityCoreVerificationOutcome {
  return { ok: false, code, reason };
}

function importPublicKey(key: IdentityKeyMaterial) {
  const der =
    key.encoding === "spki-der-base64"
      ? Buffer.from(key.publicKey, "base64")
      : Buffer.concat([
          ED25519_SPKI_PREFIX,
          Buffer.from(key.publicKey, "base64url"),
        ]);

  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function generateEd25519IdentityKey(input: {
  id: string;
  purpose: string;
  createdAt?: Date | undefined;
}): { key: IdentityKeyMaterial; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const createdAt = (input.createdAt ?? new Date()).toISOString();

  return {
    key: {
      id: input.id,
      algorithm: ED25519_ALGORITHM,
      encoding: "spki-der-base64",
      publicKey: publicKey
        .export({ format: "der", type: "spki" })
        .toString("base64"),
      purpose: input.purpose,
      status: "active",
      createdAt,
    },
    privateKey: privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64"),
  };
}

export function createEd25519Signer(input: {
  keyId: string;
  privateKey: string;
}): IdentitySigner {
  const privateKey = createPrivateKey({
    key: Buffer.from(input.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });

  return {
    keyId: input.keyId,
    async sign(payload) {
      return {
        version: A1_ENVELOPE_VERSION,
        algorithm: ED25519_ALGORITHM,
        keyId: input.keyId,
        signature: sign(
          null,
          Buffer.from(canonicalizeA1(payload)),
          privateKey,
        ).toString("base64"),
      };
    },
  };
}

export function validateIdentityKey(
  input: unknown,
): IdentityCoreVerificationOutcome {
  const key = identityKeySchema.safeParse(input);
  if (!key.success) {
    return failure("invalid_input", "Identity key is invalid");
  }

  try {
    if (importPublicKey(key.data).asymmetricKeyType !== "ed25519") {
      return failure(
        "invalid_input",
        "Identity key is not an Ed25519 public key",
      );
    }
  } catch {
    return failure("invalid_input", "Identity key is invalid");
  }

  return { ok: true };
}

export function verifyA1Signature(input: {
  payload: unknown;
  signature: SignatureEnvelope;
  key: IdentityKeyMaterial;
}): IdentityCoreVerificationOutcome {
  const signature = signatureEnvelopeSchema.safeParse(input.signature);
  const key = identityKeySchema.safeParse(input.key);
  if (!signature.success || !key.success) {
    return failure("invalid_input", "Signature envelope or key is invalid");
  }

  const keyValidation = validateIdentityKey(key.data);
  if (!keyValidation.ok) {
    return keyValidation;
  }

  if (key.data.status === "revoked") {
    return failure("key_revoked", `Signature key revoked: ${key.data.id}`);
  }

  if (signature.data.keyId !== key.data.id) {
    return failure(
      "signature_key_mismatch",
      `Signature key ${signature.data.keyId} does not match ${key.data.id}`,
    );
  }

  try {
    const verified = verify(
      null,
      Buffer.from(canonicalizeA1(input.payload)),
      importPublicKey(key.data),
      Buffer.from(signature.data.signature, "base64"),
    );
    return verified
      ? { ok: true }
      : failure("signature_invalid", "Signature verification failed");
  } catch {
    return failure("signature_invalid", "Signature verification failed");
  }
}

export async function signIdentityDocument(
  document: IdentityDocument,
  signer: IdentitySigner,
): Promise<SignedIdentityDocument> {
  const parsed = identityDocumentSchema.parse(document);
  const signature = await signer.sign(parsed);
  return signedIdentityDocumentSchema.parse({ ...parsed, signature });
}

export function verifyIdentityDocument(
  document: SignedIdentityDocument,
): IdentityCoreVerificationOutcome {
  const parsed = signedIdentityDocumentSchema.safeParse(document);
  if (!parsed.success) {
    return failure("invalid_input", "Identity document is invalid");
  }

  const key = parsed.data.keys.find(
    (entry) => entry.id === parsed.data.signature.keyId,
  );
  if (!key) {
    return failure(
      "key_not_found",
      `Signature key not found: ${parsed.data.signature.keyId}`,
    );
  }

  if (
    parsed.data.expiresAt !== undefined &&
    Date.parse(parsed.data.expiresAt) <= Date.now()
  ) {
    return failure("invalid_input", "Identity document has expired");
  }

  const { signature, ...unsignedDocument } = parsed.data;
  return verifyA1Signature({
    payload: unsignedDocument,
    signature,
    key,
  });
}
