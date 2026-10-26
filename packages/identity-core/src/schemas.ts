import { z } from "zod";
import { A1_ENVELOPE_VERSION, ED25519_ALGORITHM } from "./types.js";

const ISO_8601_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

function isValidIsoTimestamp(value: string): boolean {
  const match = ISO_8601_TIMESTAMP_PATTERN.exec(value);
  if (!match) {
    return false;
  }

  const [date, time] = value.split("T");
  if (!date || !time) {
    return false;
  }
  const [year = Number.NaN, month = Number.NaN, day = Number.NaN] = date
    .split("-")
    .map(Number);
  const [hour = Number.NaN, minute = Number.NaN, second = Number.NaN] = time
    .slice(0, 8)
    .split(":")
    .map(Number);
  const maxDay =
    month === 2
      ? year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
        ? 29
        : 28
      : [4, 6, 9, 11].includes(month)
        ? 30
        : 31;

  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= maxDay &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    !Number.isNaN(Date.parse(value))
  );
}

export const isoTimestampSchema = z
  .string()
  .regex(ISO_8601_TIMESTAMP_PATTERN, "Expected an ISO-8601 timestamp")
  .refine(isValidIsoTimestamp, {
    message: "Expected a valid ISO-8601 timestamp",
  });

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
  .strict()
  .superRefine((document, context) => {
    const keyIds = new Set<string>();
    for (const [index, key] of document.keys.entries()) {
      if (keyIds.has(key.id)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["keys", index, "id"],
          message: "Identity key IDs must be unique",
        });
      }
      keyIds.add(key.id);
    }
  });

export const signedIdentityDocumentSchema = identityDocumentSchema.extend({
  signature: signatureEnvelopeSchema,
});
