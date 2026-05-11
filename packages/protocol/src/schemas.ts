import { z } from "zod";

const isoStringSchema = z
  .string()
  .refine((value) => !Number.isNaN(Date.parse(value)), {
    message: "Expected ISO timestamp",
  });

export const permissionSchema = z.string().min(1);

export const publicKeySchema = z.object({
  id: z.string().min(1),
  type: z.literal("ed25519"),
  publicKey: z.string().min(1),
  purpose: z.enum(["root", "agent", "recovery", "signing"]),
  status: z.enum(["active", "deprecated", "revoked"]).default("active"),
  createdAt: isoStringSchema,
  expiresAt: isoStringSchema.optional(),
  deactivatedAt: isoStringSchema.optional(),
  revokedAt: isoStringSchema.optional(),
});

export const serviceEndpointSchema = z.object({
  id: z.string().min(1),
  type: z.enum(["agent", "inbox", "vault", "pay", "proof", "admin", "custom"]),
  endpoint: z.string().min(1),
  publicKeyId: z.string().min(1).optional(),
  capabilities: z.array(permissionSchema).optional(),
});

export const agentDefinitionSchema = z.object({
  id: z.string().min(1),
  owner: z.string().min(1),
  publicKeyId: z.string().min(1),
  endpoint: z.string().min(1).optional(),
  allowedCapabilities: z.array(permissionSchema),
  deniedCapabilities: z.array(permissionSchema),
  auditLogEndpoint: z.string().min(1).optional(),
  status: z.enum(["active", "revoked", "suspended"]),
  expiresAt: isoStringSchema.optional(),
});

export const verifiedClaimSchema = z.object({
  id: z.string().min(1),
  type: z.string().min(1),
  value: z.string().min(1),
  issuer: z.string().min(1).optional(),
  verifiedAt: isoStringSchema,
});

export const recoveryMethodSchema = z.object({
  id: z.string().min(1),
  type: z.enum(["email", "phone", "key", "passkey", "custom"]),
  value: z.string().min(1),
  publicKeyId: z.string().min(1).optional(),
});

export const identityManifestDraftSchema = z.object({
  id: z.string().min(1),
  version: z.string().min(1),
  publicKeys: z.array(publicKeySchema),
  services: z.array(serviceEndpointSchema),
  agents: z.array(agentDefinitionSchema),
  claims: z.array(verifiedClaimSchema),
  recovery: z.array(recoveryMethodSchema).optional(),
  updatedAt: isoStringSchema,
  expiresAt: isoStringSchema.optional(),
  signatureKeyId: z.string().min(1),
});

export const identityManifestSchema = identityManifestDraftSchema.extend({
  signature: z.string().min(1),
});

export const capabilityTokenDraftSchema = z.object({
  id: z.string().min(1),
  issuer: z.string().min(1),
  signatureKeyId: z.string().min(1),
  subject: z.string().min(1),
  audience: z.string().min(1).optional(),
  permissions: z.array(permissionSchema),
  denied: z.array(permissionSchema).optional(),
  issuedAt: isoStringSchema,
  expiresAt: isoStringSchema,
  nonce: z.string().min(1).optional(),
});

export const capabilityTokenSchema = capabilityTokenDraftSchema.extend({
  signature: z.string().min(1),
});

export const signedRequestDraftSchema = z.object({
  actor: z.string().min(1),
  issuer: z.string().min(1),
  signatureKeyId: z.string().min(1),
  capabilityToken: capabilityTokenSchema,
  method: z.string().min(1),
  path: z.string().min(1),
  bodyHash: z.string().min(1),
  timestamp: isoStringSchema,
  nonce: z.string().min(1),
});

export const signedRequestSchema = signedRequestDraftSchema.extend({
  signature: z.string().min(1),
});

export const privateIdentityRecordSchema = z.object({
  id: z.string().min(1),
  keys: z.record(
    z.object({
      id: z.string().min(1),
      type: z.literal("ed25519"),
      publicKey: z.string().min(1),
      privateKey: z.string().min(1),
      purpose: z.enum(["root", "agent", "recovery", "signing"]),
      status: z.enum(["active", "deprecated", "revoked"]).default("active"),
      createdAt: isoStringSchema,
      expiresAt: isoStringSchema.optional(),
      deactivatedAt: isoStringSchema.optional(),
      revokedAt: isoStringSchema.optional(),
    }),
  ),
  createdAt: isoStringSchema,
  updatedAt: isoStringSchema,
});

export const revocationEntrySchema = z.object({
  revokedAt: isoStringSchema,
  reason: z.string().min(1).optional(),
});

export const revocationRecordSchema = z.object({
  id: z.string().min(1),
  revokedAgents: z.record(revocationEntrySchema),
  revokedCapabilityTokens: z.record(revocationEntrySchema),
  revokedPublicKeys: z.record(revocationEntrySchema),
  updatedAt: isoStringSchema,
});
