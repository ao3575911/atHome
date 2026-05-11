import { randomBytes } from "node:crypto";
import type {
  IdentityManifest,
  MutationAuthorization,
  MutationAuthorizationDraft,
  VerificationOutcome,
} from "./types.js";
import { hashBody } from "./request.js";
import { signCanonicalPayload } from "./crypto.js";
import { verifySignedPayloadWithManifest } from "./signatures.js";

const MUTATION_WINDOW_MS = 5 * 60 * 1000;

export function createMutationAuthorization(input: {
  issuer: string;
  signatureKeyId: string;
  method: string;
  path: string;
  body?: unknown;
  privateKey: string;
  timestamp?: Date | undefined;
  nonce?: string | undefined;
}): MutationAuthorization {
  const timestamp = input.timestamp ?? new Date();
  const draft: MutationAuthorizationDraft = {
    issuer: input.issuer,
    signatureKeyId: input.signatureKeyId,
    method: input.method.toUpperCase(),
    path: input.path,
    bodyHash: hashBody(input.body),
    timestamp: timestamp.toISOString(),
    nonce: input.nonce ?? cryptoRandomNonce(),
  };

  return {
    ...draft,
    signature: signCanonicalPayload(draft, input.privateKey),
  };
}

export function verifyMutationAuthorization(
  manifest: IdentityManifest,
  authorization: MutationAuthorization,
  input: {
    method: string;
    path: string;
    body?: unknown;
    now?: Date | undefined;
  },
): VerificationOutcome {
  const now = input.now ?? new Date();

  if (authorization.issuer !== manifest.id) {
    return {
      ok: false,
      code: "request_issuer_mismatch",
      reason: "Mutation authorization issuer does not match identity",
    };
  }

  if (authorization.method.toUpperCase() !== input.method.toUpperCase()) {
    return {
      ok: false,
      code: "invalid_request_signature",
      reason: "Mutation authorization method does not match route",
    };
  }

  if (authorization.path !== input.path) {
    return {
      ok: false,
      code: "invalid_request_signature",
      reason: "Mutation authorization path does not match route",
    };
  }

  const parsedTimestamp = Date.parse(authorization.timestamp);
  if (Number.isNaN(parsedTimestamp)) {
    return {
      ok: false,
      code: "invalid_request_timestamp",
      reason: "Mutation authorization timestamp is invalid",
    };
  }

  const delta = Math.abs(now.getTime() - parsedTimestamp);
  if (delta > MUTATION_WINDOW_MS) {
    return {
      ok: false,
      code: "request_timestamp_out_of_window",
      reason: "Mutation authorization is stale",
    };
  }

  const bodyHash =
    input.body !== undefined ? hashBody(input.body) : hashBody(undefined);
  if (authorization.bodyHash.length !== 64) {
    return {
      ok: false,
      code: "invalid_body_hash",
      reason: "Mutation authorization body hash is invalid",
    };
  }

  if (authorization.bodyHash !== bodyHash) {
    return {
      ok: false,
      code: "body_hash_mismatch",
      reason: "Mutation authorization body hash does not match request body",
    };
  }

  const signatureCheck = verifySignedPayloadWithManifest(
    {
      issuer: authorization.issuer,
      signatureKeyId: authorization.signatureKeyId,
      method: authorization.method,
      path: authorization.path,
      bodyHash: authorization.bodyHash,
      timestamp: authorization.timestamp,
      nonce: authorization.nonce,
    },
    authorization.signature,
    manifest,
    authorization.signatureKeyId,
    {
      allowDeprecated: false,
      invalidSignatureCode: "invalid_request_signature",
      missingKeyCode: "missing_root_key",
      revokedKeyCode: "key_revoked",
      deprecatedKeyCode: "key_deprecated",
    },
  );

  if (!signatureCheck.ok) {
    return signatureCheck;
  }

  return { ok: true };
}

export function serializeMutationAuthorization(
  authorization: MutationAuthorization,
): string {
  return Buffer.from(JSON.stringify(authorization), "utf8").toString(
    "base64url",
  );
}

export function parseMutationAuthorization(
  value: string,
): MutationAuthorization | null {
  try {
    const decoded = Buffer.from(value, "base64url").toString("utf8");
    const parsed = JSON.parse(decoded) as MutationAuthorization;
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof parsed.issuer === "string" &&
      typeof parsed.signatureKeyId === "string" &&
      typeof parsed.method === "string" &&
      typeof parsed.path === "string" &&
      typeof parsed.bodyHash === "string" &&
      typeof parsed.timestamp === "string" &&
      typeof parsed.nonce === "string" &&
      typeof parsed.signature === "string"
    ) {
      return parsed;
    }

    return null;
  } catch {
    return null;
  }
}

function cryptoRandomNonce(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}
