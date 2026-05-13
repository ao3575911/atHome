import type {
  CapabilityToken,
  IdentityManifest,
  RevocationRecord,
  ReplayStore,
  SignedRequest,
  SignedRequestDraft,
  VerificationOutcome,
} from "./types.js";
import { canonicalize } from "./canonical.js";
import { canPerform, resolvePermissionForRequest } from "./authorization.js";
import { randomNonce, sha256, signCanonicalPayload } from "./crypto.js";
import { verifyCapabilityToken } from "./capabilities.js";
import { verifyIdentityManifest } from "./manifest.js";
import { verifySignedPayloadWithManifest } from "./signatures.js";

const REQUEST_WINDOW_MS = 5 * 60 * 1000;

export function hashBody(body: unknown): string {
  if (body === undefined) {
    return sha256("");
  }

  if (typeof body === "string" || Buffer.isBuffer(body)) {
    return sha256(body);
  }

  return sha256(canonicalize(body));
}

export function createSignedRequest(input: {
  actor: string;
  issuer: string;
  signatureKeyId: string;
  capabilityToken: CapabilityToken;
  method: string;
  path: string;
  body?: unknown;
  privateKey: string;
  timestamp?: Date | undefined;
  nonce?: string | undefined;
}): SignedRequest {
  const timestamp = input.timestamp ?? new Date();
  const draft: SignedRequestDraft = {
    actor: input.actor,
    issuer: input.issuer,
    signatureKeyId: input.signatureKeyId,
    capabilityToken: input.capabilityToken,
    method: input.method,
    path: input.path,
    bodyHash: hashBody(input.body),
    timestamp: timestamp.toISOString(),
    nonce: input.nonce ?? randomNonce(),
  };

  return { ...draft, signature: signCanonicalPayload(draft, input.privateKey) };
}

export function createSignedRequestDraft(input: {
  actor: string;
  issuer: string;
  signatureKeyId: string;
  capabilityToken: CapabilityToken;
  method: string;
  path: string;
  body?: unknown;
  timestamp?: Date | undefined;
  nonce?: string | undefined;
}): SignedRequestDraft {
  const timestamp = input.timestamp ?? new Date();
  return {
    actor: input.actor,
    issuer: input.issuer,
    signatureKeyId: input.signatureKeyId,
    capabilityToken: input.capabilityToken,
    method: input.method,
    path: input.path,
    bodyHash: hashBody(input.body),
    timestamp: timestamp.toISOString(),
    nonce: input.nonce ?? randomNonce(),
  };
}

export function signSignedRequestDraft(
  draft: SignedRequestDraft,
  signature: string,
): SignedRequest {
  return { ...draft, signature };
}

function verifyRequestTime(timestamp: string, now: Date): VerificationOutcome {
  const parsed = Date.parse(timestamp);

  if (Number.isNaN(parsed)) {
    return { ok: false, reason: "invalid_request_timestamp" };
  }

  const delta = Math.abs(now.getTime() - parsed);
  if (delta > REQUEST_WINDOW_MS) {
    return { ok: false, reason: "request_timestamp_out_of_window" };
  }

  return { ok: true };
}

export async function verifySignedRequest(input: {
  manifest: IdentityManifest;
  request: SignedRequest;
  replayStore?: ReplayStore;
  revocations?: RevocationRecord | null;
  expectedAudience?: string | undefined;
  body?: unknown;
  now?: Date;
}): Promise<VerificationOutcome> {
  const now = input.now ?? new Date();
  const manifestCheck = verifyIdentityManifest(input.manifest);
  if (!manifestCheck.ok) {
    return manifestCheck;
  }

  if (input.request.issuer !== input.manifest.id) {
    return { ok: false, reason: "request_issuer_mismatch" };
  }

  const agent = input.manifest.agents.find(
    (entry) => entry.id === input.request.actor,
  );
  if (!agent) {
    return { ok: false, reason: "request_actor_not_registered" };
  }

  if (agent.status === "revoked") {
    return {
      ok: false,
      code: "agent_revoked",
      reason: "Agent has been revoked",
    };
  }

  if (agent.status === "suspended") {
    return { ok: false, code: "agent_suspended", reason: "Agent is suspended" };
  }

  if (agent.expiresAt && Date.parse(agent.expiresAt) <= now.getTime()) {
    return { ok: false, code: "agent_expired", reason: "Agent has expired" };
  }

  const requestedPermission = resolvePermissionForRequest(
    input.request.method,
    input.request.path,
  );
  const tokenCheck = verifyCapabilityToken(
    input.manifest,
    input.request.capabilityToken,
    requestedPermission,
    now,
    {
      expectedAudience: input.expectedAudience,
      revocations: input.revocations,
    },
  );
  if (!tokenCheck.ok) {
    return tokenCheck;
  }

  const publicKey = input.manifest.publicKeys.find(
    (entry) => entry.id === agent.publicKeyId,
  );
  if (!publicKey) {
    return { ok: false, reason: "agent_public_key_not_found" };
  }

  if (input.request.signatureKeyId !== agent.publicKeyId) {
    return {
      ok: false,
      code: "request_signature_key_mismatch",
      reason: `Request signature key ${input.request.signatureKeyId} does not match agent key ${agent.publicKeyId}`,
    };
  }

  const draft: SignedRequestDraft = {
    actor: input.request.actor,
    issuer: input.request.issuer,
    signatureKeyId: input.request.signatureKeyId,
    capabilityToken: input.request.capabilityToken,
    method: input.request.method,
    path: input.request.path,
    bodyHash: input.request.bodyHash,
    timestamp: input.request.timestamp,
    nonce: input.request.nonce,
  };

  const signatureCheck = verifySignedPayloadWithManifest(
    draft,
    input.request.signature,
    input.manifest,
    input.request.signatureKeyId,
    {
      allowDeprecated: true,
      invalidSignatureCode: "invalid_request_signature",
      missingKeyCode: "agent_public_key_not_found",
      revokedKeyCode: "key_revoked",
    },
  );

  if (!signatureCheck.ok) {
    return signatureCheck;
  }

  if (publicKey.status === "revoked") {
    return {
      ok: false,
      code: "key_revoked",
      reason: "Agent signing key has been revoked",
    };
  }

  if (input.revocations?.revokedPublicKeys[input.request.signatureKeyId]) {
    return {
      ok: false,
      code: "key_revoked",
      reason: "Agent signing key has been revoked",
    };
  }

  const tokenId = input.request.capabilityToken.id;
  if (input.revocations?.revokedCapabilityTokens[tokenId]) {
    return {
      ok: false,
      code: "token_revoked",
      reason: "Capability token has been revoked",
    };
  }

  if (input.revocations?.revokedAgents[input.request.actor]) {
    return {
      ok: false,
      code: "agent_revoked",
      reason: "Agent has been revoked",
    };
  }

  const bodyCheck =
    input.body !== undefined
      ? hashBody(input.body) === input.request.bodyHash
      : input.request.bodyHash.length === 64;
  if (!bodyCheck) {
    return {
      ok: false,
      code:
        input.body !== undefined ? "body_hash_mismatch" : "invalid_body_hash",
      reason:
        input.body !== undefined
          ? "Request body hash does not match observed body"
          : "Request body hash is invalid",
    };
  }

  const tokenPolicy = canPerform({
    requestedPermission,
    tokenPermissions: input.request.capabilityToken.permissions,
    tokenDenied: input.request.capabilityToken.denied,
    agentAllowed: agent.allowedCapabilities,
    agentDenied: agent.deniedCapabilities,
    audience: input.request.capabilityToken.audience,
    expectedAudience: input.expectedAudience,
  });
  if (!tokenPolicy.ok) {
    return tokenPolicy;
  }

  const timestampCheck = verifyRequestTime(input.request.timestamp, now);
  if (!timestampCheck.ok) {
    return timestampCheck;
  }

  if (input.replayStore) {
    const scope = input.request.actor;
    const seen = await input.replayStore.hasNonce(scope, input.request.nonce);
    if (seen) {
      return {
        ok: false,
        code: "nonce_replayed",
        reason: "Nonce has already been used",
      };
    }

    await input.replayStore.recordNonce(
      scope,
      input.request.nonce,
      new Date(now.getTime() + REQUEST_WINDOW_MS).toISOString(),
    );
  }

  return {
    ok: true,
    details: {
      requestedPermission,
      actor: input.request.actor,
    },
  };
}

export function verifyRequestBodyHash(
  body: unknown,
  expectedBodyHash: string,
): VerificationOutcome {
  const actual = hashBody(body);
  if (actual !== expectedBodyHash) {
    return {
      ok: false,
      code: "body_hash_mismatch",
      reason: "Request body hash does not match observed body",
    };
  }

  return { ok: true };
}

export function verifyRequestBodyHashOnly(
  expectedBodyHash: string,
): VerificationOutcome {
  if (expectedBodyHash.length !== 64) {
    return {
      ok: false,
      code: "invalid_body_hash",
      reason: "Request body hash is invalid",
    };
  }

  return { ok: true };
}
