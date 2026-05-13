import Fastify from "fastify";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { fileURLToPath } from "node:url";
import {
  type RegistryBackend,
  IdentityRegistry,
  LocalJsonStore,
  type KeyCustodyProvider,
  createMemoryKeyCustodyProvider,
  createMemoryWitnessService,
  parseMutationAuthorization,
  verifyMutationAuthorization,
} from "@athome/protocol";
import { z } from "zod";
import {
  agentDefinitionSchema,
  agentBodySchema as agentJsonSchema,
  capabilityTokenSchema,
  createIdentityBodySchema as createIdentityJsonSchema,
  createIdentityResponseSchema,
  errorResponseSchema,
  identityManifestSchema,
  issueCapabilityTokenBodySchema as issueCapabilityTokenJsonSchema,
  issueCapabilityTokenResponseSchema,
  manifestResponseSchema,
  publicKeySchema,
  registerAgentResponseSchema,
  registryEventSchema,
  registryFreshnessResponseSchema,
  registryFreshnessSchema,
  registryStreamResponseSchema,
  registryCheckpointSchema,
  resolveBodySchema as resolveJsonSchema,
  resolveResponseSchema,
  revocationResponseSchema,
  rotateRootKeyResponseSchema,
  serviceEndpointBodySchema as serviceEndpointJsonSchema,
  serviceEndpointSchema,
  signedRequestSchema,
  verifyWitnessBodySchema as verifyWitnessJsonSchema,
  verifyWitnessResponseSchema,
  witnessReceiptSchema,
  verifyCapabilityBodySchema as verifyCapabilityJsonSchema,
  verifyResponseSchema,
  verifyRequestBodySchema as verifyRequestJsonSchema,
} from "./schemas.js";
import { buildOpenApiDocument } from "./openapi.js";
import { ApiError, apiError, toApiError, toErrorEnvelope } from "./errors.js";

const createIdentityBody = z.object({
  id: z.string().min(1),
});

const issueTokenBody = z.object({
  subject: z.string().min(1),
  permissions: z.array(z.string().min(1)),
  denied: z.array(z.string().min(1)).optional(),
  audience: z.string().min(1).optional(),
  ttlSeconds: z.number().int().positive().optional(),
  nonce: z.string().min(1).optional(),
});

const resolveBody = z.object({
  name: z.string().min(1),
});

const registryQuery = z.object({
  identityId: z.string().min(1),
});

const capabilityVerifyBody = z.object({
  token: z.object({
    id: z.string().min(1),
    issuer: z.string().min(1),
    signatureKeyId: z.string().min(1),
    subject: z.string().min(1),
    audience: z.string().min(1).optional(),
    permissions: z.array(z.string().min(1)),
    denied: z.array(z.string().min(1)).optional(),
    issuedAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    nonce: z.string().min(1).optional(),
    signature: z.string().min(1),
  }),
  permission: z.string().min(1),
  expectedAudience: z.string().min(1).optional(),
});

const requestVerifyBody = z.object({
  request: z.object({
    actor: z.string().min(1),
    issuer: z.string().min(1),
    signatureKeyId: z.string().min(1),
    capabilityToken: capabilityVerifyBody.shape.token,
    method: z.string().min(1),
    path: z.string().min(1),
    bodyHash: z.string().min(1),
    timestamp: z.string().datetime(),
    nonce: z.string().min(1),
    signature: z.string().min(1),
  }),
  body: z.unknown().optional(),
  expectedAudience: z.string().min(1).optional(),
});

const witnessVerifyBody = z.object({
  identityId: z.string().min(1),
  eventId: z.string().min(1),
  receiptId: z.string().min(1),
});

const agentBody = z.object({
  id: z.string().min(1),
  allowedCapabilities: z.array(z.string().min(1)),
  deniedCapabilities: z.array(z.string().min(1)),
  endpoint: z.string().min(1).optional(),
  auditLogEndpoint: z.string().min(1).optional(),
  expiresAt: z.string().datetime().optional(),
  status: z.enum(["active", "revoked", "suspended"]).optional(),
});

function validationError(
  message: string,
  details: Record<string, unknown> = {},
): ApiError {
  return apiError("invalid_request", message, 400, details);
}

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw validationError("Invalid request body", {
      issues: parsed.error.issues,
    });
  }

  return parsed.data;
}

function buildResponse<T extends object>(payload: T): T {
  return payload;
}

function buildKeyCustody(privateKeyExported: boolean): {
  mode: "browser-held" | "kms" | "passkey";
  privateKeyExported: boolean;
  guidance: string;
} {
  return {
    mode: "browser-held",
    privateKeyExported,
    guidance:
      "Private key material was not returned. Use client-side signing, passkeys, or managed custody for production.",
  };
}

function requireProductionCustody(): void {
  if (process.env.NODE_ENV === "production") {
    throw apiError(
      "key_custody_required",
      "Registry mutation requires production key custody support",
      403,
    );
  }
}

async function requireMutationAuthorization(
  registry: IdentityRegistry,
  identityId: string,
  method: string,
  path: string,
  body: unknown,
  headerValue: unknown,
): Promise<void> {
  if (typeof headerValue !== "string" || headerValue.length === 0) {
    throw apiError(
      "mutation_unauthorized",
      "Mutation authorization is required",
      401,
    );
  }

  const authorization = parseMutationAuthorization(headerValue);
  if (!authorization) {
    throw apiError(
      "mutation_unauthorized",
      "Mutation authorization is invalid",
      401,
    );
  }

  const manifest = await registry.getManifest(identityId);
  if (!manifest) {
    throw apiError("identity_not_found", "Identity not found", 404);
  }

  const verification = verifyMutationAuthorization(manifest, authorization, {
    method,
    path,
    body,
  });

  if (!verification.ok) {
    throw apiError(
      verification.code ?? "mutation_unauthorized",
      verification.reason ?? "Mutation authorization failed",
      verification.code === "request_issuer_mismatch" ? 403 : 401,
      verification.details ?? {},
    );
  }
}

const defaultDataDir =
  process.env.DATA_DIR ??
  fileURLToPath(new URL("../../../data", import.meta.url));

export interface ApiConfig {
  custody?: KeyCustodyProvider | undefined;
}

export function buildApp(
  store: RegistryBackend = new LocalJsonStore(defaultDataDir),
  config: ApiConfig = {},
) {
  const custody =
    config.custody ?? createMemoryKeyCustodyProvider({ recordStore: store });
  const witness = createMemoryWitnessService();
  const registry = new IdentityRegistry(store, custody, witness);
  const app = Fastify({ logger: false });

  app.register(swagger, {
    openapi: {
      openapi: "3.0.3",
      info: {
        title: "atHome API",
        version: "0.2.0",
      },
    },
  });
  app.register(swaggerUi, {
    routePrefix: "/docs",
    uiConfig: {
      docExpansion: "list",
    },
    transformSpecification: () => buildOpenApiDocument(app),
    transformSpecificationClone: false,
    staticCSP: true,
  });
  app.addSchema({ $id: "ErrorResponse", ...errorResponseSchema });
  app.addSchema({ $id: "PublicKey", ...publicKeySchema });
  app.addSchema({ $id: "ServiceEndpoint", ...serviceEndpointSchema });
  app.addSchema({ $id: "AgentDefinition", ...agentDefinitionSchema });
  app.addSchema({
    $id: "VerifiedClaim",
    ...identityManifestSchema.properties.claims.items,
  });
  app.addSchema({
    $id: "RecoveryMethod",
    ...identityManifestSchema.properties.recovery.items,
  });
  app.addSchema({ $id: "IdentityManifest", ...identityManifestSchema });
  app.addSchema({ $id: "CapabilityToken", ...capabilityTokenSchema });
  app.addSchema({ $id: "SignedRequest", ...signedRequestSchema });
  app.addSchema({ $id: "RegistryEvent", ...registryEventSchema });
  app.addSchema({ $id: "WitnessReceipt", ...witnessReceiptSchema });
  app.addSchema({ $id: "RegistryCheckpoint", ...registryCheckpointSchema });
  app.addSchema({ $id: "RegistryFreshness", ...registryFreshnessSchema });
  app.addSchema({
    $id: "VerificationOutcome",
    ...verifyResponseSchema.properties.verification,
  });

  app.setErrorHandler((error, _request, reply) => {
    const api = toApiError(error);
    reply.code(api.statusCode).send(toErrorEnvelope(api));
  });

  app.setNotFoundHandler((request, reply) => {
    reply.code(404).send(
      toErrorEnvelope(
        apiError("not_found", "Route not found", 404, {
          method: request.method,
          url: request.url,
        }),
      ),
    );
  });

  app.after(() => {
    app.get(
      "/health",
      {
        schema: {
          response: {
            200: {
              type: "object",
              required: ["ok"],
              properties: {
                ok: { const: true },
              },
              additionalProperties: false,
            },
          },
        },
      },
      async () => ({ ok: true }),
    );

    app.get(
      "/openapi.json",
      {
        schema: {
          hide: true,
          response: {
            200: { type: "object", additionalProperties: true },
          },
        },
      },
      async () => buildOpenApiDocument(app),
    );

    app.post(
      "/identities",
      {
        schema: {
          body: createIdentityJsonSchema,
          response: {
            201: createIdentityResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
            409: errorResponseSchema,
            500: errorResponseSchema,
          },
        },
      },
      async (request, reply) => {
        const parsed = parseBody(createIdentityBody, request.body);

        if (process.env.NODE_ENV === "production") {
          throw apiError(
            "key_custody_required",
            "Identity bootstrap requires client-side key custody in production",
            403,
          );
        }

        let result;
        try {
          result = await registry.createIdentity(parsed.id);
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          if (/already exists/i.test(message)) {
            throw apiError("identity_already_exists", message, 409);
          }

          throw error;
        }

        return reply.code(201).send(
          buildResponse({
            ok: true,
            manifest: result.manifest,
            rootKeyId: result.rootKey.id,
            custody: buildKeyCustody(false),
          }),
        );
      },
    );

    app.get(
      "/identities/:id",
      {
        schema: {
          params: {
            type: "object",
            required: ["id"],
            properties: {
              id: { type: "string" },
            },
            additionalProperties: false,
          },
          response: {
            200: manifestResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request, reply) => {
        const params = request.params as { id: string };
        const manifest = await registry.getManifest(params.id);
        if (!manifest) {
          throw apiError("identity_not_found", "Identity not found", 404);
        }

        return buildResponse({ ok: true, manifest });
      },
    );

    app.post(
      "/identities/:id/services",
      {
        schema: {
          params: {
            type: "object",
            required: ["id"],
            properties: {
              id: { type: "string" },
            },
            additionalProperties: false,
          },
          body: serviceEndpointJsonSchema,
          response: {
            200: manifestResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
            409: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const params = request.params as { id: string };
        requireProductionCustody();
        const service = parseBody(
          z.object({
            id: z.string().min(1),
            type: z.enum([
              "agent",
              "inbox",
              "vault",
              "pay",
              "proof",
              "admin",
              "custom",
            ]),
            endpoint: z.string().min(1),
            publicKeyId: z.string().min(1).optional(),
            capabilities: z.array(z.string().min(1)).optional(),
          }),
          request.body,
        );

        await requireMutationAuthorization(
          registry,
          params.id,
          request.method,
          request.url.split("?")[0] ?? request.url,
          service,
          request.headers["x-home-authorization"],
        );
        const manifest = await registry.registerService(params.id, service);
        return buildResponse({ ok: true, manifest });
      },
    );

    app.post(
      "/identities/:id/agents",
      {
        schema: {
          params: {
            type: "object",
            required: ["id"],
            properties: {
              id: { type: "string" },
            },
            additionalProperties: false,
          },
          body: agentJsonSchema,
          response: {
            201: registerAgentResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
            409: errorResponseSchema,
          },
        },
      },
      async (request, reply) => {
        const params = request.params as { id: string };
        requireProductionCustody();
        const parsed = parseBody(agentBody, request.body);
        await requireMutationAuthorization(
          registry,
          params.id,
          request.method,
          request.url.split("?")[0] ?? request.url,
          parsed,
          request.headers["x-home-authorization"],
        );
        const result = await registry.registerAgent(params.id, parsed);

        return reply.code(201).send(
          buildResponse({
            ok: true,
            manifest: result.manifest,
            agent: result.agent,
            publicKeyId: result.agentKey.id,
            custody: buildKeyCustody(false),
          }),
        );
      },
    );

    app.post(
      "/identities/:id/capability-tokens",
      {
        schema: {
          params: {
            type: "object",
            required: ["id"],
            properties: {
              id: { type: "string" },
            },
            additionalProperties: false,
          },
          body: issueCapabilityTokenJsonSchema,
          response: {
            201: issueCapabilityTokenResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
            409: errorResponseSchema,
          },
        },
      },
      async (request, reply) => {
        const params = request.params as { id: string };
        requireProductionCustody();
        const parsed = parseBody(issueTokenBody, request.body);
        await requireMutationAuthorization(
          registry,
          params.id,
          request.method,
          request.url.split("?")[0] ?? request.url,
          parsed,
          request.headers["x-home-authorization"],
        );
        const token = await registry.issueCapabilityToken(params.id, parsed);

        return reply.code(201).send(
          buildResponse({
            ok: true,
            token,
            tokenId: token.id,
          }),
        );
      },
    );

    app.post(
      "/identities/:id/agents/:agentId/revoke",
      {
        schema: {
          params: {
            type: "object",
            required: ["id", "agentId"],
            properties: {
              id: { type: "string" },
              agentId: { type: "string" },
            },
            additionalProperties: false,
          },
          response: {
            200: revocationResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const params = request.params as { id: string; agentId: string };
        requireProductionCustody();
        await requireMutationAuthorization(
          registry,
          params.id,
          request.method,
          request.url.split("?")[0] ?? request.url,
          undefined,
          request.headers["x-home-authorization"],
        );
        const manifest = await registry.revokeAgent(params.id, params.agentId);
        const revokedAt = new Date().toISOString();

        return buildResponse({
          ok: true,
          revocation: {
            identityId: params.id,
            kind: "agent" as const,
            id: params.agentId,
            revokedAt,
          },
          manifest,
        });
      },
    );

    app.post(
      "/identities/:id/capability-tokens/:tokenId/revoke",
      {
        schema: {
          params: {
            type: "object",
            required: ["id", "tokenId"],
            properties: {
              id: { type: "string" },
              tokenId: { type: "string" },
            },
            additionalProperties: false,
          },
          response: {
            200: revocationResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const params = request.params as { id: string; tokenId: string };
        requireProductionCustody();
        await requireMutationAuthorization(
          registry,
          params.id,
          request.method,
          request.url.split("?")[0] ?? request.url,
          undefined,
          request.headers["x-home-authorization"],
        );
        const manifest = await registry.revokeCapabilityToken(
          params.id,
          params.tokenId,
        );
        const revokedAt = new Date().toISOString();
        return buildResponse({
          ok: true,
          revocation: {
            identityId: params.id,
            kind: "token" as const,
            id: params.tokenId,
            revokedAt,
          },
          manifest,
        });
      },
    );

    app.post(
      "/identities/:id/keys/:keyId/revoke",
      {
        schema: {
          params: {
            type: "object",
            required: ["id", "keyId"],
            properties: {
              id: { type: "string" },
              keyId: { type: "string" },
            },
            additionalProperties: false,
          },
          response: {
            200: revocationResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const params = request.params as { id: string; keyId: string };
        requireProductionCustody();
        await requireMutationAuthorization(
          registry,
          params.id,
          request.method,
          request.url.split("?")[0] ?? request.url,
          undefined,
          request.headers["x-home-authorization"],
        );
        const manifest = await registry.revokePublicKey(
          params.id,
          params.keyId,
        );
        const revokedAt = new Date().toISOString();
        return buildResponse({
          ok: true,
          revocation: {
            identityId: params.id,
            kind: "key" as const,
            id: params.keyId,
            revokedAt,
          },
          manifest,
        });
      },
    );

    app.post(
      "/identities/:id/keys/root/rotate",
      {
        schema: {
          params: {
            type: "object",
            required: ["id"],
            properties: {
              id: { type: "string" },
            },
            additionalProperties: false,
          },
          response: {
            201: rotateRootKeyResponseSchema,
            401: errorResponseSchema,
            403: errorResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request, reply) => {
        const params = request.params as { id: string };
        requireProductionCustody();
        await requireMutationAuthorization(
          registry,
          params.id,
          request.method,
          request.url.split("?")[0] ?? request.url,
          undefined,
          request.headers["x-home-authorization"],
        );

        const currentManifest = await registry.getManifest(params.id);
        if (!currentManifest) {
          throw apiError("identity_not_found", "Identity not found", 404);
        }

        const result = await registry.rotateRootKey(params.id);
        const rotatedAt = result.manifest.updatedAt;

        return reply.code(201).send(
          buildResponse({
            ok: true,
            manifest: result.manifest,
            rootKeyId: result.newRootKey.id,
            rotated: {
              oldRootKeyId: currentManifest.signatureKeyId,
              newRootKeyId: result.newRootKey.id,
              rotatedAt,
            },
            custody: buildKeyCustody(false),
          }),
        );
      },
    );

    app.post(
      "/resolve",
      {
        schema: {
          body: resolveJsonSchema,
          response: {
            200: resolveResponseSchema,
            400: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const parsed = parseBody(resolveBody, request.body);
        const result = await registry.resolve(parsed.name);
        return buildResponse({ ok: true, ...result });
      },
    );

    app.post(
      "/verify/capability",
      {
        schema: {
          body: verifyCapabilityJsonSchema,
          response: {
            200: verifyResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const parsed = parseBody(capabilityVerifyBody, request.body);
        const verification = await registry.verifyCapability(
          parsed.token.issuer,
          parsed.token,
          parsed.permission,
          { expectedAudience: parsed.expectedAudience },
        );

        return buildResponse({
          ok: true,
          verification,
        });
      },
    );

    app.post(
      "/verify/request",
      {
        schema: {
          body: verifyRequestJsonSchema,
          response: {
            200: verifyResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const parsed = parseBody(requestVerifyBody, request.body);
        const verification = await registry.verifyRequest(
          parsed.request.issuer,
          parsed.request,
          {
            body: parsed.body,
            expectedAudience: parsed.expectedAudience,
          },
        );

        return buildResponse({
          ok: true,
          verification,
        });
      },
    );

    app.get(
      "/registry/stream",
      {
        schema: {
          querystring: {
            type: "object",
            required: ["identityId"],
            properties: {
              identityId: { type: "string" },
            },
            additionalProperties: false,
          },
          response: {
            200: registryStreamResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const query = parseBody(registryQuery, request.query);
        const manifest = await registry.getManifest(query.identityId);
        if (!manifest) {
          throw apiError("identity_not_found", "Identity not found", 404);
        }

        return buildResponse({
          ok: true,
          identityId: query.identityId,
          events: await store.listEvents(query.identityId),
          witnessReceipts: await store.listWitnessReceipts(query.identityId),
        });
      },
    );

    app.get(
      "/registry/freshness",
      {
        schema: {
          querystring: {
            type: "object",
            required: ["identityId"],
            properties: {
              identityId: { type: "string" },
            },
            additionalProperties: false,
          },
          response: {
            200: registryFreshnessResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const query = parseBody(registryQuery, request.query);
        const manifest = await registry.getManifest(query.identityId);
        if (!manifest) {
          throw apiError("identity_not_found", "Identity not found", 404);
        }

        return buildResponse({
          ok: true,
          freshness: await store.getFreshnessMetadata(query.identityId),
        });
      },
    );

    app.post(
      "/verify/witness",
      {
        schema: {
          body: verifyWitnessJsonSchema,
          response: {
            200: verifyWitnessResponseSchema,
            400: errorResponseSchema,
            404: errorResponseSchema,
          },
        },
      },
      async (request) => {
        const parsed = parseBody(witnessVerifyBody, request.body);
        const events = await store.listEvents(parsed.identityId);
        const event = events.find((entry) => entry.id === parsed.eventId);
        const receipts = await store.listWitnessReceipts(parsed.identityId);
        const receipt = receipts.find(
          (entry) => entry.receiptId === parsed.receiptId,
        );

        if (!event || !receipt) {
          throw apiError(
            "witness_invalid",
            "Witness event or receipt was not found",
            404,
          );
        }

        return buildResponse({
          ok: true,
          event,
          receipt,
          verification: await witness.verifyReceipt(event, receipt),
        });
      },
    );
  });

  return app;
}
