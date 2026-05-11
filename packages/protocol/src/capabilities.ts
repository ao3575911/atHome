import type {
  CapabilityToken,
  IdentityManifest,
  RevocationRecord,
  VerificationOutcome,
} from "./types.js";
import {
  createCapabilityTokenDraft,
  createCapabilityTokenId,
  signCapabilityToken,
  verifyCapabilityTokenSignature,
  verifyCapabilityTokenTimeWindow,
} from "./manifest.js";
import { canPerform } from "./authorization.js";

export function issueCapabilityToken(input: {
  manifest: IdentityManifest;
  rootPrivateKey: string;
  subject: string;
  permissions: string[];
  denied?: string[] | undefined;
  audience?: string | undefined;
  ttlSeconds?: number | undefined;
  nonce?: string | undefined;
  issuedAt?: Date | undefined;
}): CapabilityToken {
  const agent = input.manifest.agents.find(
    (entry) => entry.id === input.subject,
  );

  if (!agent) {
    throw new Error(`Unknown agent: ${input.subject}`);
  }

  const permissions = [...new Set(input.permissions)].sort();
  const denied = input.denied ? [...new Set(input.denied)].sort() : undefined;

  const policy = canPerform({
    requestedPermission: permissions[0] ?? "",
    tokenPermissions: permissions,
    tokenDenied: denied,
    agentAllowed: agent.allowedCapabilities,
    agentDenied: agent.deniedCapabilities,
    audience: input.audience,
    expectedAudience: input.audience,
  });

  if (!policy.ok && policy.code === "permission_denied") {
    throw new Error(policy.reason ?? "Permission denied");
  }

  for (const permission of permissions) {
    if (!agent.allowedCapabilities.includes(permission)) {
      throw new Error(`Permission not allowed for agent: ${permission}`);
    }

    if (agent.deniedCapabilities.includes(permission)) {
      throw new Error(`Permission denied for agent: ${permission}`);
    }
  }

  for (const permission of denied ?? []) {
    if (permissions.includes(permission)) {
      throw new Error(
        `Capability token cannot both allow and deny: ${permission}`,
      );
    }
  }

  const issuedAt = input.issuedAt ?? new Date();
  const expiresAt = new Date(
    issuedAt.getTime() + (input.ttlSeconds ?? 3600) * 1000,
  );
  const draft = createCapabilityTokenDraft({
    id: createCapabilityTokenId(),
    issuer: input.manifest.id,
    signatureKeyId: input.manifest.signatureKeyId,
    subject: input.subject,
    audience: input.audience,
    permissions,
    denied,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    nonce: input.nonce,
  });

  return signCapabilityToken(draft, input.rootPrivateKey);
}

export function verifyCapabilityToken(
  manifest: IdentityManifest,
  token: CapabilityToken,
  requestedPermission?: string,
  now = new Date(),
  options: {
    expectedAudience?: string | undefined;
    revocations?: RevocationRecord | null | undefined;
  } = {},
): VerificationOutcome {
  if (token.issuer !== manifest.id) {
    return {
      ok: false,
      code: "token_issuer_mismatch",
      reason: "Capability token issuer does not match manifest",
    };
  }

  const signatureCheck = verifyCapabilityTokenSignature(manifest, token);
  if (!signatureCheck.ok) {
    return signatureCheck;
  }

  if (options.revocations?.revokedCapabilityTokens[token.id]) {
    return {
      ok: false,
      code: "token_revoked",
      reason: "Capability token has been revoked",
    };
  }

  const timeWindow = verifyCapabilityTokenTimeWindow(token, now);
  if (!timeWindow.ok) {
    return timeWindow;
  }

  const agent = manifest.agents.find((entry) => entry.id === token.subject);
  if (!agent) {
    return {
      ok: false,
      code: "token_subject_not_registered",
      reason: "Capability token subject is not registered",
    };
  }

  const canPerformResult = canPerform({
    requestedPermission: requestedPermission ?? token.permissions[0] ?? "",
    tokenPermissions: token.permissions,
    tokenDenied: token.denied,
    agentAllowed: agent.allowedCapabilities,
    agentDenied: agent.deniedCapabilities,
    audience: token.audience,
    expectedAudience: options.expectedAudience,
    agentStatus: agent.status,
    tokenExpiresAt: token.expiresAt,
    tokenRevoked: Boolean(
      options.revocations?.revokedCapabilityTokens[token.id],
    ),
    tokenSignatureKeyStatus: manifest.publicKeys.find(
      (entry) => entry.id === token.signatureKeyId,
    )?.status,
    now,
  });

  if (!canPerformResult.ok) {
    return canPerformResult;
  }

  return { ok: true };
}
