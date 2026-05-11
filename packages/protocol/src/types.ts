export type KeyType = "ed25519";
export type KeyPurpose = "root" | "agent" | "recovery" | "signing";
export type KeyStatus = "active" | "deprecated" | "revoked";

export const STANDARD_PERMISSIONS = [
  "profile:read",
  "email:draft",
  "logs:analyze",
  "payment:send",
  "vault:delete",
  "social:post",
] as const;

export type StandardPermission = (typeof STANDARD_PERMISSIONS)[number];
export type Permission = StandardPermission | (string & {});

export interface PublicKey {
  id: string;
  type: KeyType;
  publicKey: string;
  purpose: KeyPurpose;
  status: KeyStatus;
  createdAt: string;
  expiresAt?: string | undefined;
  deactivatedAt?: string | undefined;
  revokedAt?: string | undefined;
}

export interface PrivateKeyMaterial extends PublicKey {
  privateKey: string;
}

export interface ServiceEndpoint {
  id: string;
  type: "agent" | "inbox" | "vault" | "pay" | "proof" | "admin" | "custom";
  endpoint: string;
  publicKeyId?: string | undefined;
  capabilities?: Permission[] | undefined;
}

export interface AgentDefinition {
  id: string;
  owner: string;
  publicKeyId: string;
  endpoint?: string | undefined;
  allowedCapabilities: Permission[];
  deniedCapabilities: Permission[];
  auditLogEndpoint?: string | undefined;
  status: "active" | "revoked" | "suspended";
  expiresAt?: string | undefined;
}

export interface VerifiedClaim {
  id: string;
  type: string;
  value: string;
  issuer?: string | undefined;
  verifiedAt: string;
}

export interface RecoveryMethod {
  id: string;
  type: "email" | "phone" | "key" | "passkey" | "custom";
  value: string;
  publicKeyId?: string | undefined;
}

export interface IdentityManifest {
  id: string;
  version: string;
  publicKeys: PublicKey[];
  services: ServiceEndpoint[];
  agents: AgentDefinition[];
  claims: VerifiedClaim[];
  recovery?: RecoveryMethod[] | undefined;
  updatedAt: string;
  expiresAt?: string | undefined;
  signatureKeyId: string;
  signature: string;
}

export type IdentityManifestDraft = Omit<IdentityManifest, "signature">;

export interface CapabilityToken {
  id: string;
  issuer: string;
  signatureKeyId: string;
  subject: string;
  audience?: string | undefined;
  permissions: Permission[];
  denied?: Permission[] | undefined;
  issuedAt: string;
  expiresAt: string;
  nonce?: string | undefined;
  signature: string;
}

export type CapabilityTokenDraft = Omit<CapabilityToken, "signature">;

export interface SignedRequest {
  actor: string;
  issuer: string;
  signatureKeyId: string;
  capabilityToken: CapabilityToken;
  method: string;
  path: string;
  bodyHash: string;
  timestamp: string;
  nonce: string;
  signature: string;
}

export type SignedRequestDraft = Omit<SignedRequest, "signature">;

export interface MutationAuthorization {
  issuer: string;
  signatureKeyId: string;
  method: string;
  path: string;
  bodyHash: string;
  timestamp: string;
  nonce: string;
  signature: string;
}

export type MutationAuthorizationDraft = Omit<
  MutationAuthorization,
  "signature"
>;

export interface PrivateIdentityRecord {
  id: string;
  keys: Record<string, PrivateKeyMaterial>;
  createdAt: string;
  updatedAt: string;
}

export interface RevokedEntry {
  revokedAt: string;
  reason?: string | undefined;
}

export interface RevocationRecord {
  id: string;
  revokedAgents: Record<string, RevokedEntry>;
  revokedCapabilityTokens: Record<string, RevokedEntry>;
  revokedPublicKeys: Record<string, RevokedEntry>;
  updatedAt: string;
}

export interface WitnessReceipt {
  receiptId: string;
  identityId: string;
  eventId: string;
  eventHash: string;
  kind: "agent" | "token" | "key";
  subjectId: string;
  revokedAt: string;
  payloadHash: string;
  logIndex: number;
  witnessKeyId: string;
  signature: string;
}

export type AuthorizationFailureCode =
  | "permission_not_granted"
  | "permission_denied"
  | "audience_mismatch"
  | "audience_required"
  | "agent_revoked"
  | "agent_suspended"
  | "agent_expired"
  | "token_expired"
  | "token_revoked"
  | "key_revoked"
  | "token_issuer_mismatch"
  | "token_subject_not_registered"
  | "token_signature_invalid"
  | "invalid_token_timestamps"
  | "token_issued_in_future"
  | "token_not_active"
  | "request_timestamp_out_of_window"
  | "invalid_request_timestamp"
  | "request_issuer_mismatch"
  | "request_actor_not_registered"
  | "request_signature_key_mismatch"
  | "agent_public_key_not_found"
  | "invalid_request_signature"
  | "body_hash_mismatch"
  | "invalid_body_hash"
  | "nonce_replayed"
  | "missing_root_key"
  | "invalid_manifest_signature"
  | "key_not_found"
  | "key_deprecated"
  | "token_revoked_by_registry"
  | "unknown_permission"
  | "witness_receipt_invalid";

export interface ReplayStore {
  hasNonce(scope: string, nonce: string): Promise<boolean>;
  recordNonce(scope: string, nonce: string, expiresAt: string): Promise<void>;
}

export interface VerificationOutcome {
  ok: boolean;
  code?: AuthorizationFailureCode;
  reason?: string;
  details?: Record<string, unknown>;
}
