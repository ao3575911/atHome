export const OPENAPI_SCHEMA_NAMES = [
  "AgentDefinition",
  "CapabilityToken",
  "ErrorResponse",
  "IdentityManifest",
  "PublicKey",
  "RecoveryMethod",
  "ServiceEndpoint",
  "SignedRequest",
  "VerificationOutcome",
  "VerifiedClaim",
] as const;

export type OpenApiSchemaName = (typeof OPENAPI_SCHEMA_NAMES)[number];
