export {
  HomeApiError,
  HomeClient,
  createExternalMutationSigner,
  createHomeClient,
  createIdentity,
  createMutationAuthorization,
  createRootMutationSigner,
  createSignedRequest,
  issueCapabilityToken,
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
export type * from "@home/protocol";
