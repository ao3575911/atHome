export {
  HomeApiError,
  HomeClient,
  createExternalMutationSigner,
  createHomeClient,
  createIdentity,
  createMutationAuthorization,
  createRootMutationSigner,
  createSignedRequest,
  createWebCryptoMutationSigner,
  getReadiness,
  getRevocationState,
  getStatus,
  issueCapabilityToken,
  listAuditEvents,
  listIdentityEvents,
  listWitnessReceipts,
  resolveName,
  revokeAgent,
  revokeCapabilityToken,
  revokeKey,
  rotateRootKey,
  verifyCapability,
  verifySignedRequest,
} from "./client.js";
export {
  OPENAPI_SCHEMA_NAMES,
  type OpenApiSchemaName,
} from "./openapi-schema-names.js";
export type {
  AuditEventsResponse,
  IdentityEventsResponse,
  ReadinessResponse,
  RevocationStateResponse,
  StatusResponse,
  WebCryptoMutationSignerInput,
  WitnessReceiptsResponse,
} from "./client.js";
export type * from "@home/protocol";
