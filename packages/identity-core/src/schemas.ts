import { z } from "zod";
import { A1_ENVELOPE_VERSION, ED25519_ALGORITHM } from "./types.js";

const ISO_8601_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

export const isoTimestampSchema = z
  .string()
  .regex(ISO_8601_TIMESTAMP_PATTERN, "Expected an ISO-8601 timestamp")
  .datetime({ offset: true, message: "Expected a valid ISO-8601 timestamp" });

export function isA1Timestamp(value: string): boolean {
  return isoTimestampSchema.safeParse(value).success;
}

const base64Schema = z.string().min(1);

export const identityKeySchema = z
  .object({
    id: z.string().min(1),
    algorithm: z.literal(ED25519_ALGORITHM),
    encoding: z.enum(["spki-der-base64", "raw-base64url"]),
    publicKey: base64Schema,
    purpose: z.string().min(1),
    status: z.enum(["active", "deprecated", "revoked"]).default("active"),
    createdAt: isoTimestampSchema,
    expiresAt: isoTimestampSchema.optional(),
    revokedAt: isoTimestampSchema.optional(),
  })
  .strict();

export const signatureEnvelopeSchema = z
  .object({
    version: z.literal(A1_ENVELOPE_VERSION),
    algorithm: z.literal(ED25519_ALGORITHM),
    keyId: z.string().min(1),
    signature: base64Schema,
  })
  .strict();

export const identityDocumentSchema = z
  .object({
    version: z.literal(A1_ENVELOPE_VERSION),
    id: z.string().min(1),
    keys: z.array(identityKeySchema).min(1),
    createdAt: isoTimestampSchema,
    updatedAt: isoTimestampSchema,
    expiresAt: isoTimestampSchema.optional(),
  })
  .strict();

export const signedIdentityDocumentSchema = identityDocumentSchema.extend({
  signature: signatureEnvelopeSchema,
});
