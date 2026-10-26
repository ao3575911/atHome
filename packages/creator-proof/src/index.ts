import {
  isA1Timestamp,
  type IdentityKeyMaterial,
  type IdentitySigner,
  type SignatureEnvelope,
  verifyA1Signature,
} from "@athome/identity-core";
import type { AuthorizationPolicyHook } from "@athome/protocol";
import { z } from "zod";

const isoTimestampSchema = z
  .string()
  .refine(isA1Timestamp, "Expected a valid ISO-8601 timestamp");

const signatureEnvelopeSchema = z
  .object({
    version: z.literal("a1"),
    algorithm: z.literal("Ed25519"),
    keyId: z.string().min(1),
    signature: z.string().min(1),
  })
  .strict();

export const creatorClaimSchema = z
  .object({
    type: z.string().min(1),
    value: z.unknown(),
  })
  .strict();

export const creatorProofDraftSchema = z
  .object({
    version: z.literal("a1"),
    id: z.string().min(1),
    issuer: z.string().min(1),
    subject: z.string().min(1),
    claims: z.array(creatorClaimSchema).min(1),
    issuedAt: isoTimestampSchema,
    expiresAt: isoTimestampSchema.optional(),
    nonce: z.string().min(1).optional(),
  })
  .strict();

export const creatorProofSchema = creatorProofDraftSchema.extend({
  signature: signatureEnvelopeSchema,
});

export type CreatorProofDraft = z.infer<typeof creatorProofDraftSchema>;
export type CreatorProof = z.infer<typeof creatorProofSchema>;

export interface CreatorTrustAnchor {
  issuer: string;
  key: IdentityKeyMaterial;
}

export type CreatorProofVerificationCode =
  | "invalid_proof"
  | "creator_relationship_missing"
  | "proof_expiry_required"
  | "proof_expired"
  | "proof_not_active"
  | "proof_revoked"
  | "untrusted_issuer"
  | "signature_invalid";

export interface CreatorProofVerificationOutcome {
  ok: boolean;
  code?: CreatorProofVerificationCode | undefined;
  reason?: string | undefined;
  proof?: CreatorProof | undefined;
}

export interface CreatorProofPolicyContext {
  creatorProof?: unknown;
}

const CREATOR_RELATIONSHIP_CLAIMS = new Set([
  "creator.control",
  "creator.issued",
]);

function failure(
  code: CreatorProofVerificationCode,
  reason: string,
): CreatorProofVerificationOutcome {
  return { ok: false, code, reason };
}

function unsignedProof(proof: CreatorProof): CreatorProofDraft {
  const { signature: _signature, ...draft } = proof;
  return draft;
}

export function hasCreatorRelationshipClaim(proof: CreatorProof): boolean {
  return proof.claims.some((claim) =>
    CREATOR_RELATIONSHIP_CLAIMS.has(claim.type),
  );
}

export function createCreatorProofDraft(
  input: CreatorProofDraft,
): CreatorProofDraft {
  return creatorProofDraftSchema.parse(input);
}

export async function signCreatorProof(
  draft: CreatorProofDraft,
  signer: IdentitySigner,
): Promise<CreatorProof> {
  const parsed = creatorProofDraftSchema.parse(draft);
  const signature = await signer.sign(parsed);
  return creatorProofSchema.parse({ ...parsed, signature });
}

export function verifyCreatorProof(input: {
  proof: unknown;
  trustAnchors: readonly CreatorTrustAnchor[];
  now?: Date | undefined;
  requireExpiry?: boolean | undefined;
  maxClockSkewMs?: number | undefined;
  revokedProofIds?: ReadonlySet<string> | undefined;
}): CreatorProofVerificationOutcome {
  const parsed = creatorProofSchema.safeParse(input.proof);
  if (!parsed.success) {
    return failure("invalid_proof", "Creator proof is invalid");
  }

  const proof = parsed.data;
  if (!hasCreatorRelationshipClaim(proof)) {
    return failure(
      "creator_relationship_missing",
      "Creator proof does not declare a creator relationship",
    );
  }

  const now = input.now ?? new Date();
  const requireExpiry = input.requireExpiry ?? true;
  const issuedAt = Date.parse(proof.issuedAt);
  const expiresAt = proof.expiresAt ? Date.parse(proof.expiresAt) : undefined;
  const maxClockSkewMs = input.maxClockSkewMs ?? 5 * 60 * 1000;

  if (requireExpiry && !proof.expiresAt) {
    return failure(
      "proof_expiry_required",
      "Creator proof expiration is required",
    );
  }

  if (issuedAt > now.getTime() + maxClockSkewMs) {
    return failure("proof_not_active", "Creator proof is not active");
  }

  if (expiresAt !== undefined && expiresAt <= now.getTime()) {
    return failure("proof_expired", "Creator proof has expired");
  }

  if (input.revokedProofIds?.has(proof.id)) {
    return failure("proof_revoked", "Creator proof has been revoked");
  }

  const anchor = input.trustAnchors.find(
    (candidate) =>
      candidate.issuer === proof.issuer &&
      candidate.key.id === proof.signature.keyId,
  );
  if (!anchor) {
    return failure("untrusted_issuer", "Creator proof issuer is not trusted");
  }

  const signature = proof.signature as SignatureEnvelope;
  const signatureVerification = verifyA1Signature({
    payload: unsignedProof(proof),
    signature,
    key: anchor.key,
  });
  if (!signatureVerification.ok) {
    return failure(
      "signature_invalid",
      signatureVerification.reason ?? "Creator proof signature is invalid",
    );
  }

  return { ok: true, proof };
}

export function createCreatorProofPolicy(input: {
  trustAnchors: readonly CreatorTrustAnchor[];
  requiredClaimTypes?: readonly string[] | undefined;
  now?: () => Date;
  revokedProofIds?: ReadonlySet<string> | undefined;
}): AuthorizationPolicyHook {
  return {
    evaluate(request) {
      const context = request.context as CreatorProofPolicyContext | undefined;
      if (!context?.creatorProof) {
        return {
          ok: false,
          code: "creator_proof_required",
          reason: "A verified creator proof is required",
        };
      }

      const verification = verifyCreatorProof({
        proof: context.creatorProof,
        trustAnchors: input.trustAnchors,
        now: input.now?.(),
        revokedProofIds: input.revokedProofIds,
      });
      if (!verification.ok || !verification.proof) {
        return {
          ok: false,
          code: "creator_proof_invalid",
          reason: "Creator proof verification failed",
        };
      }

      if (verification.proof.subject !== request.request.actor) {
        return {
          ok: false,
          code: "creator_proof_invalid",
          reason: "Creator proof subject does not match request actor",
        };
      }

      if (
        input.requiredClaimTypes?.some(
          (type) =>
            !verification.proof?.claims.some((claim) => claim.type === type),
        )
      ) {
        return {
          ok: false,
          code: "creator_proof_invalid",
          reason: "Creator proof is missing a required claim",
        };
      }

      return { ok: true };
    },
  };
}
