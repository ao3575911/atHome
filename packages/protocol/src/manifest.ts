import type {
  AgentDefinition,
  CapabilityToken,
  CapabilityTokenDraft,
  IdentityManifest,
  IdentityManifestDraft,
  PrivateKeyMaterial,
  PublicKey,
  ServiceEndpoint,
  VerificationOutcome,
} from "./types.js";
import { randomUUID } from "node:crypto";
import { signCanonicalPayload, verifyCanonicalPayload } from "./crypto.js";
import { verifySignedPayloadWithManifest } from "./signatures.js";

export function createIdentityManifestDraft(
  id: string,
  rootPublicKey: PublicKey,
  updatedAt: string,
): IdentityManifestDraft {
  return {
    id,
    version: "1.0.0",
    publicKeys: [rootPublicKey],
    services: [],
    agents: [],
    claims: [],
    updatedAt,
    signatureKeyId: rootPublicKey.id,
  };
}

export function signIdentityManifest(
  draft: IdentityManifestDraft,
  rootPrivateKey: PrivateKeyMaterial,
): IdentityManifest {
  const signature = signCanonicalPayload(draft, rootPrivateKey.privateKey);
  return { ...draft, signatureKeyId: rootPrivateKey.id, signature };
}

export function verifyIdentityManifest(
  manifest: IdentityManifest,
): VerificationOutcome {
  const draft: IdentityManifestDraft = {
    id: manifest.id,
    version: manifest.version,
    publicKeys: manifest.publicKeys,
    services: manifest.services,
    agents: manifest.agents,
    claims: manifest.claims,
    recovery: manifest.recovery,
    updatedAt: manifest.updatedAt,
    expiresAt: manifest.expiresAt,
    signatureKeyId: manifest.signatureKeyId,
  };

  return verifySignedPayloadWithManifest(
    draft,
    manifest.signature,
    manifest,
    manifest.signatureKeyId,
    {
      allowDeprecated: false,
      invalidSignatureCode: "invalid_manifest_signature",
      missingKeyCode: "missing_root_key",
      revokedKeyCode: "invalid_manifest_signature",
      deprecatedKeyCode: "key_deprecated",
    },
  );
}

export function addPublicKey(
  manifest: IdentityManifest,
  publicKey: PublicKey,
): IdentityManifest {
  return {
    ...manifest,
    publicKeys: [...manifest.publicKeys, publicKey],
    updatedAt: new Date().toISOString(),
  };
}

export function addService(
  manifest: IdentityManifest,
  service: ServiceEndpoint,
): IdentityManifest {
  return {
    ...manifest,
    services: [...manifest.services, service],
    updatedAt: new Date().toISOString(),
  };
}

export function addAgent(
  manifest: IdentityManifest,
  agent: AgentDefinition,
): IdentityManifest {
  return {
    ...manifest,
    agents: [...manifest.agents, agent],
    updatedAt: new Date().toISOString(),
  };
}

export function updatePublicKey(
  manifest: IdentityManifest,
  keyId: string,
  patch: Partial<PublicKey>,
): IdentityManifest {
  return {
    ...manifest,
    publicKeys: manifest.publicKeys.map((key) =>
      key.id === keyId ? { ...key, ...patch } : key,
    ),
    updatedAt: new Date().toISOString(),
  };
}

export function createCapabilityTokenDraft(input: {
  id: string;
  issuer: string;
  signatureKeyId: string;
  subject: string;
  audience?: string | undefined;
  permissions: CapabilityToken["permissions"];
  denied?: CapabilityToken["denied"] | undefined;
  issuedAt: string;
  expiresAt: string;
  nonce?: string | undefined;
}): CapabilityTokenDraft {
  return {
    id: input.id,
    issuer: input.issuer,
    signatureKeyId: input.signatureKeyId,
    subject: input.subject,
    audience: input.audience,
    permissions: [...input.permissions].sort(),
    denied: input.denied ? [...input.denied].sort() : undefined,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };
}

export function signCapabilityToken(
  draft: CapabilityTokenDraft,
  rootPrivateKey: string,
): CapabilityToken {
  return { ...draft, signature: signCanonicalPayload(draft, rootPrivateKey) };
}

export function verifyCapabilityTokenSignature(
  manifest: IdentityManifest,
  token: CapabilityToken,
): VerificationOutcome {
  const draft: CapabilityTokenDraft = {
    id: token.id,
    issuer: token.issuer,
    signatureKeyId: token.signatureKeyId,
    subject: token.subject,
    audience: token.audience,
    permissions: token.permissions,
    denied: token.denied,
    issuedAt: token.issuedAt,
    expiresAt: token.expiresAt,
    nonce: token.nonce,
  };

  return verifySignedPayloadWithManifest(
    draft,
    token.signature,
    manifest,
    token.signatureKeyId,
    {
      allowDeprecated: true,
      invalidSignatureCode: "token_signature_invalid",
      missingKeyCode: "key_not_found",
      revokedKeyCode: "key_revoked",
    },
  );
}

export function verifyCapabilityTokenTimeWindow(
  token: CapabilityToken,
  now = new Date(),
): VerificationOutcome {
  const issuedAt = Date.parse(token.issuedAt);
  const expiresAt = Date.parse(token.expiresAt);
  const current = now.getTime();

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
    return { ok: false, reason: "invalid_token_timestamps" };
  }

  if (issuedAt > current + 5 * 60 * 1000) {
    return { ok: false, reason: "token_issued_in_future" };
  }

  if (expiresAt <= current) {
    return { ok: false, reason: "token_expired" };
  }

  return { ok: true };
}

export function createCapabilityTokenId(): string {
  return randomUUID();
}
