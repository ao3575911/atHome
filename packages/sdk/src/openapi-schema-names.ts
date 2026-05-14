export const OPENAPI_SCHEMA_NAMES = [
  "AgentDefinition",
  "CapabilityToken",
  "ErrorResponse",
  "IdentityManifest",
  "PublicKey",
  "RecoveryMethod",
  "RegistryCheckpoint",
  "RegistryEvent",
  "RegistryFreshness",
  "ServiceEndpoint",
  "SignedRequest",
  "VerificationOutcome",
  "VerifiedClaim",
  "WitnessReceipt",
] as const;

export type OpenApiSchemaName = (typeof OPENAPI_SCHEMA_NAMES)[number];
