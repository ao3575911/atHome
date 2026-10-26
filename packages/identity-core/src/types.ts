export const A1_ENVELOPE_VERSION = "a1" as const;
export const ED25519_ALGORITHM = "Ed25519" as const;

export type A1KeyEncoding = "spki-der-base64" | "raw-base64url";
export type A1KeyStatus = "active" | "deprecated" | "revoked";

export interface IdentityKeyMaterial {
  id: string;
  algorithm: typeof ED25519_ALGORITHM;
  encoding: A1KeyEncoding;
  publicKey: string;
  purpose: string;
  status: A1KeyStatus;
  createdAt: string;
  expiresAt?: string | undefined;
  revokedAt?: string | undefined;
}

export interface IdentityDocument {
  version: typeof A1_ENVELOPE_VERSION;
  id: string;
  keys: IdentityKeyMaterial[];
  createdAt: string;
  updatedAt: string;
  expiresAt?: string | undefined;
}

export interface SignatureEnvelope {
  version: typeof A1_ENVELOPE_VERSION;
  algorithm: typeof ED25519_ALGORITHM;
  keyId: string;
  signature: string;
}

export interface SignedIdentityDocument extends IdentityDocument {
  signature: SignatureEnvelope;
}

export interface IdentitySigner {
  readonly keyId: string;
  sign(payload: unknown): Promise<SignatureEnvelope>;
}

export type IdentityCoreVerificationCode =
  | "invalid_input"
  | "key_not_found"
  | "key_revoked"
  | "key_expired"
  | "document_expired"
  | "untrusted_key"
  | "signature_key_mismatch"
  | "signature_invalid";

export interface IdentityCoreVerificationOutcome {
  ok: boolean;
  code?: IdentityCoreVerificationCode | undefined;
  reason?: string | undefined;
}

export interface PseudonymRotationAdapter {
  derivePseudonym(input: {
    identity: IdentityDocument;
    epoch: Date;
  }): Promise<string>;
}
