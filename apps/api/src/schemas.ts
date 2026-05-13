const stringSchema = { type: "string" } as const;

export const errorResponseSchema = {
  type: "object",
  required: ["ok", "error"],
  properties: {
    ok: { const: false },
    error: {
      type: "object",
      required: ["code", "message", "details"],
      properties: {
        code: stringSchema,
        message: stringSchema,
        details: {
          type: "object",
          additionalProperties: true,
        },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
} as const;

export const publicKeySchema = {
  type: "object",
  required: ["id", "type", "publicKey", "purpose", "status", "createdAt"],
  properties: {
    id: stringSchema,
    type: { const: "ed25519" },
    publicKey: stringSchema,
    purpose: { enum: ["root", "agent", "recovery", "signing"] },
    status: { enum: ["active", "deprecated", "revoked"] },
    createdAt: stringSchema,
    expiresAt: stringSchema,
    deactivatedAt: stringSchema,
    revokedAt: stringSchema,
  },
  additionalProperties: false,
} as const;

export const serviceEndpointSchema = {
  type: "object",
  required: ["id", "type", "endpoint"],
  properties: {
    id: stringSchema,
    type: {
      enum: ["agent", "inbox", "vault", "pay", "proof", "admin", "custom"],
    },
    endpoint: stringSchema,
    publicKeyId: stringSchema,
    capabilities: {
      type: "array",
      items: stringSchema,
    },
  },
  additionalProperties: false,
} as const;

export const agentDefinitionSchema = {
  type: "object",
  required: [
    "id",
    "owner",
    "publicKeyId",
    "allowedCapabilities",
    "deniedCapabilities",
    "status",
  ],
  properties: {
    id: stringSchema,
    owner: stringSchema,
    publicKeyId: stringSchema,
    endpoint: stringSchema,
    allowedCapabilities: {
      type: "array",
      items: stringSchema,
    },
    deniedCapabilities: {
      type: "array",
      items: stringSchema,
    },
    auditLogEndpoint: stringSchema,
    status: { enum: ["active", "revoked", "suspended"] },
    expiresAt: stringSchema,
  },
  additionalProperties: false,
} as const;

export const verifiedClaimSchema = {
  type: "object",
  required: ["id", "type", "value", "verifiedAt"],
  properties: {
    id: stringSchema,
    type: stringSchema,
    value: stringSchema,
    issuer: stringSchema,
    verifiedAt: stringSchema,
  },
  additionalProperties: false,
} as const;

export const recoveryMethodSchema = {
  type: "object",
  required: ["id", "type", "value"],
  properties: {
    id: stringSchema,
    type: { enum: ["email", "phone", "key", "passkey", "custom"] },
    value: stringSchema,
    publicKeyId: stringSchema,
  },
  additionalProperties: false,
} as const;

export const identityManifestSchema = {
  type: "object",
  required: [
    "id",
    "version",
    "publicKeys",
    "services",
    "agents",
    "claims",
    "updatedAt",
    "signatureKeyId",
    "signature",
  ],
  properties: {
    id: stringSchema,
    version: stringSchema,
    publicKeys: { type: "array", items: publicKeySchema },
    services: { type: "array", items: serviceEndpointSchema },
    agents: { type: "array", items: agentDefinitionSchema },
    claims: { type: "array", items: verifiedClaimSchema },
    recovery: { type: "array", items: recoveryMethodSchema },
    updatedAt: stringSchema,
    expiresAt: stringSchema,
    signatureKeyId: stringSchema,
    signature: stringSchema,
  },
  additionalProperties: false,
} as const;

export const capabilityTokenSchema = {
  type: "object",
  required: [
    "id",
    "issuer",
    "signatureKeyId",
    "subject",
    "permissions",
    "issuedAt",
    "expiresAt",
    "signature",
  ],
  properties: {
    id: stringSchema,
    issuer: stringSchema,
    signatureKeyId: stringSchema,
    subject: stringSchema,
    audience: stringSchema,
    permissions: {
      type: "array",
      items: stringSchema,
    },
    denied: {
      type: "array",
      items: stringSchema,
    },
    issuedAt: stringSchema,
    expiresAt: stringSchema,
    nonce: stringSchema,
    signature: stringSchema,
  },
  additionalProperties: false,
} as const;

export const signedRequestSchema = {
  type: "object",
  required: [
    "actor",
    "issuer",
    "signatureKeyId",
    "capabilityToken",
    "method",
    "path",
    "bodyHash",
    "timestamp",
    "nonce",
    "signature",
  ],
  properties: {
    actor: stringSchema,
    issuer: stringSchema,
    signatureKeyId: stringSchema,
    capabilityToken: capabilityTokenSchema,
    method: stringSchema,
    path: stringSchema,
    bodyHash: stringSchema,
    timestamp: stringSchema,
    nonce: stringSchema,
    signature: stringSchema,
  },
  additionalProperties: false,
} as const;

export const verificationOutcomeSchema = {
  type: "object",
  required: ["ok"],
  properties: {
    ok: { type: "boolean" },
    code: stringSchema,
    reason: stringSchema,
    details: {
      type: "object",
      additionalProperties: true,
    },
  },
  additionalProperties: false,
} as const;

export const keyCustodySchema = {
  type: "object",
  required: ["mode", "privateKeyExported", "guidance"],
  properties: {
    mode: { enum: ["local-dev-server-generated", "local-dev-export"] },
    privateKeyExported: { type: "boolean" },
    guidance: stringSchema,
  },
  additionalProperties: false,
} as const;

export const createIdentityBodySchema = {
  type: "object",
  required: ["id"],
  properties: {
    id: stringSchema,
  },
  additionalProperties: false,
} as const;

export const serviceEndpointBodySchema = serviceEndpointSchema;

export const agentBodySchema = {
  type: "object",
  required: ["id", "allowedCapabilities", "deniedCapabilities"],
  properties: {
    id: stringSchema,
    allowedCapabilities: { type: "array", items: stringSchema },
    deniedCapabilities: { type: "array", items: stringSchema },
    endpoint: stringSchema,
    auditLogEndpoint: stringSchema,
    expiresAt: stringSchema,
    status: { enum: ["active", "revoked", "suspended"] },
  },
  additionalProperties: false,
} as const;

export const issueCapabilityTokenBodySchema = {
  type: "object",
  required: ["subject", "permissions"],
  properties: {
    subject: stringSchema,
    permissions: { type: "array", items: stringSchema },
    denied: { type: "array", items: stringSchema },
    audience: stringSchema,
    ttlSeconds: { type: "integer", minimum: 1 },
    nonce: stringSchema,
  },
  additionalProperties: false,
} as const;

export const resolveBodySchema = {
  type: "object",
  required: ["name"],
  properties: {
    name: stringSchema,
  },
  additionalProperties: false,
} as const;

export const verifyCapabilityBodySchema = {
  type: "object",
  required: ["token", "permission"],
  properties: {
    token: capabilityTokenSchema,
    permission: stringSchema,
    expectedAudience: stringSchema,
  },
  additionalProperties: false,
} as const;

export const verifyRequestBodySchema = {
  type: "object",
  required: ["request"],
  properties: {
    request: signedRequestSchema,
    body: {},
    expectedAudience: stringSchema,
  },
  additionalProperties: false,
} as const;

export const manifestResponseSchema = {
  type: "object",
  required: ["ok", "manifest"],
  properties: {
    ok: { const: true },
    manifest: identityManifestSchema,
  },
  additionalProperties: true,
} as const;

export const createIdentityResponseSchema = {
  type: "object",
  required: ["ok", "manifest", "rootKeyId", "custody"],
  properties: {
    ok: { const: true },
    manifest: identityManifestSchema,
    rootKeyId: stringSchema,
    custody: keyCustodySchema,
    privateKey: stringSchema,
  },
  additionalProperties: true,
} as const;

export const registerAgentResponseSchema = {
  type: "object",
  required: ["ok", "manifest", "agent", "publicKeyId", "custody"],
  properties: {
    ok: { const: true },
    manifest: identityManifestSchema,
    agent: agentDefinitionSchema,
    publicKeyId: stringSchema,
    custody: keyCustodySchema,
    privateKey: stringSchema,
  },
  additionalProperties: true,
} as const;

export const rotateRootKeyResponseSchema = {
  type: "object",
  required: ["ok", "manifest", "rootKeyId", "rotated", "custody"],
  properties: {
    ok: { const: true },
    manifest: identityManifestSchema,
    rootKeyId: stringSchema,
    rotated: {
      type: "object",
      required: ["oldRootKeyId", "newRootKeyId", "rotatedAt"],
      properties: {
        oldRootKeyId: stringSchema,
        newRootKeyId: stringSchema,
        rotatedAt: stringSchema,
      },
      additionalProperties: false,
    },
    custody: keyCustodySchema,
    privateKey: stringSchema,
  },
  additionalProperties: true,
} as const;

export const issueCapabilityTokenResponseSchema = {
  type: "object",
  required: ["ok", "token", "tokenId"],
  properties: {
    ok: { const: true },
    token: capabilityTokenSchema,
    tokenId: stringSchema,
  },
  additionalProperties: true,
} as const;

export const resolveResponseSchema = {
  type: "object",
  required: ["ok", "rootIdentity", "resolvedType", "manifestSignatureValid"],
  properties: {
    ok: { const: true },
    rootIdentity: {
      anyOf: [{ type: "null" }, identityManifestSchema],
    },
    resolvedType: { enum: ["root", "service", "agent", "unknown"] },
    resolvedEntry: {
      anyOf: [
        serviceEndpointSchema,
        {
          type: "object",
          required: ["id", "publicKeyId"],
          properties: {
            id: stringSchema,
            publicKeyId: stringSchema,
          },
          additionalProperties: false,
        },
      ],
    },
    publicKey: {
      anyOf: [{ type: "null" }, publicKeySchema],
    },
    manifestSignatureValid: { type: "boolean" },
  },
  additionalProperties: true,
} as const;

export const verifyResponseSchema = {
  type: "object",
  required: ["ok", "verification"],
  properties: {
    ok: { const: true },
    verification: verificationOutcomeSchema,
  },
  additionalProperties: true,
} as const;

export const revocationResponseSchema = {
  type: "object",
  required: ["ok", "revocation"],
  properties: {
    ok: { const: true },
    revocation: {
      type: "object",
      required: ["identityId", "kind", "id", "revokedAt"],
      properties: {
        identityId: stringSchema,
        kind: { enum: ["agent", "token", "key"] },
        id: stringSchema,
        revokedAt: stringSchema,
        reason: stringSchema,
      },
      additionalProperties: false,
    },
    manifest: identityManifestSchema,
  },
  additionalProperties: true,
} as const;
