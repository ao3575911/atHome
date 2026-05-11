import type {
  IdentityManifest,
  PublicKey,
  VerificationOutcome,
} from "./types.js";
import { verifyCanonicalPayload } from "./crypto.js";

function failure(
  code: VerificationOutcome["code"],
  reason: string,
): VerificationOutcome {
  return code ? { ok: false, code, reason } : { ok: false, reason };
}

export function findPublicKey(
  manifest: IdentityManifest,
  keyId: string,
): PublicKey | undefined {
  return manifest.publicKeys.find((key) => key.id === keyId);
}

export function verifySignedPayloadWithManifest(
  payload: unknown,
  signature: string,
  manifest: IdentityManifest,
  signatureKeyId: string,
  options: {
    allowDeprecated: boolean;
    invalidSignatureCode: VerificationOutcome["code"];
    missingKeyCode: VerificationOutcome["code"];
    revokedKeyCode: VerificationOutcome["code"];
    deprecatedKeyCode?: VerificationOutcome["code"];
  },
): VerificationOutcome {
  const key = findPublicKey(manifest, signatureKeyId);
  if (!key) {
    return failure(
      options.missingKeyCode,
      `Signature key not found: ${signatureKeyId}`,
    );
  }

  if (key.status === "revoked") {
    return failure(
      options.revokedKeyCode,
      `Signature key revoked: ${signatureKeyId}`,
    );
  }

  if (!options.allowDeprecated && key.status === "deprecated") {
    return failure(
      options.deprecatedKeyCode ?? options.invalidSignatureCode,
      `Signature key deprecated: ${signatureKeyId}`,
    );
  }

  if (!verifyCanonicalPayload(payload, signature, key.publicKey)) {
    return failure(
      options.invalidSignatureCode,
      "Signature verification failed",
    );
  }

  return { ok: true };
}
