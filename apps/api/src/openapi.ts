import type { FastifyInstance } from "fastify";

type OpenApiSchemaMap = Record<string, unknown>;

type OpenApiOperation = {
  operationId?: string;
  summary?: string;
  description?: string;
  tags?: string[];
  security?: Array<Record<string, string[]>>;
  [key: string]: unknown;
};

type OpenApiDocument = {
  components?: {
    schemas?: OpenApiSchemaMap;
    [key: string]: unknown;
  };
  paths?: Record<string, Record<string, OpenApiOperation>>;
  [key: string]: unknown;
};

const anonymousSchemaKey = /^def-\d+$/;
const schemaRefPrefix = "#/components/schemas/";

const operationMetadata: Record<
  string,
  {
    operationId: string;
    summary: string;
    tags: string[];
    mutation?: boolean;
  }
> = {
  "GET /health": {
    operationId: "healthCheck",
    summary: "Check API health",
    tags: ["System"],
  },
  "POST /identities": {
    operationId: "createIdentity",
    summary: "Bootstrap a local development root identity",
    tags: ["Identities"],
  },
  "GET /identities/{id}": {
    operationId: "getIdentity",
    summary: "Fetch a signed identity manifest",
    tags: ["Identities"],
  },
  "POST /identities/{id}/services": {
    operationId: "registerService",
    summary: "Register a service endpoint under an identity",
    tags: ["Registry"],
    mutation: true,
  },
  "POST /identities/{id}/agents": {
    operationId: "registerAgent",
    summary: "Register a delegated agent under an identity",
    tags: ["Registry"],
    mutation: true,
  },
  "POST /identities/{id}/capability-tokens": {
    operationId: "issueCapabilityToken",
    summary: "Issue a capability token for a registered agent",
    tags: ["Capabilities"],
    mutation: true,
  },
  "POST /identities/{id}/agents/{agentId}/revoke": {
    operationId: "revokeAgent",
    summary: "Revoke a registered agent",
    tags: ["Revocations"],
    mutation: true,
  },
  "POST /identities/{id}/capability-tokens/{tokenId}/revoke": {
    operationId: "revokeCapabilityToken",
    summary: "Revoke a capability token",
    tags: ["Revocations"],
    mutation: true,
  },
  "POST /identities/{id}/keys/{keyId}/revoke": {
    operationId: "revokePublicKey",
    summary: "Revoke a public key",
    tags: ["Revocations"],
    mutation: true,
  },
  "POST /resolve": {
    operationId: "resolveName",
    summary: "Resolve a root identity, service, or agent name",
    tags: ["Resolution"],
  },
  "POST /verify/capability": {
    operationId: "verifyCapability",
    summary:
      "Verify a capability token against a permission and optional audience",
    tags: ["Verification"],
  },
  "POST /verify/request": {
    operationId: "verifyRequest",
    summary: "Verify a signed agent request",
    tags: ["Verification"],
  },
  "POST /verify/witness": {
    operationId: "verifyWitnessReceipt",
    summary: "Verify a stored witness receipt against a registry event",
    tags: ["Verification"],
  },
  "GET /registry/stream": {
    operationId: "getRegistryStream",
    summary: "List append-only registry events and witness receipts",
    tags: ["Registry"],
  },
  "GET /registry/freshness": {
    operationId: "getRegistryFreshness",
    summary: "Read registry freshness metadata",
    tags: ["Registry"],
  },
};

export function buildOpenApiDocument(app: FastifyInstance): OpenApiDocument {
  return enhanceOpenApiDocument(
    normalizeOpenApiDocument(app.swagger() as unknown as OpenApiDocument),
  );
}

export function normalizeOpenApiDocument(
  document: OpenApiDocument,
): OpenApiDocument {
  const cloned = JSON.parse(JSON.stringify(document)) as OpenApiDocument;
  const components = cloned.components;
  const schemas = components?.schemas;

  if (!schemas) {
    return cloned;
  }

  const renameMap = new Map<string, string>();
  const usedNames = new Set(
    Object.keys(schemas).filter((name) => !anonymousSchemaKey.test(name)),
  );
  const renamedSchemas: OpenApiSchemaMap = {};

  for (const [key, schema] of Object.entries(schemas)) {
    if (!anonymousSchemaKey.test(key)) {
      renamedSchemas[key] = schema;
      continue;
    }

    const preferredName = deriveStableSchemaName(schema, key);
    const stableName = reserveUniqueName(preferredName, usedNames);
    renameMap.set(key, stableName);
    renamedSchemas[stableName] = schema;
  }

  components.schemas = renamedSchemas;
  return rewriteSchemaReferences(cloned, renameMap);
}

export function enhanceOpenApiDocument(
  document: OpenApiDocument,
): OpenApiDocument {
  const components = (document.components ??= {});
  components.securitySchemes = {
    ...(typeof components.securitySchemes === "object" &&
    components.securitySchemes !== null
      ? (components.securitySchemes as Record<string, unknown>)
      : {}),
    AtHomeMutationAuthorization: {
      type: "apiKey",
      in: "header",
      name: "x-home-authorization",
      description:
        "Base64url-encoded signed mutation authorization over the exact method, path, and request body.",
    },
  };

  for (const [path, methods] of Object.entries(document.paths ?? {})) {
    for (const [method, operation] of Object.entries(methods)) {
      const metadata = operationMetadata[`${method.toUpperCase()} ${path}`];
      if (!metadata || !operation || typeof operation !== "object") {
        continue;
      }

      operation.operationId ??= metadata.operationId;
      operation.summary ??= metadata.summary;
      operation.tags ??= metadata.tags;
      if (metadata.mutation) {
        operation.security ??= [{ AtHomeMutationAuthorization: [] }];
      }
    }
  }

  return document;
}

function deriveStableSchemaName(schema: unknown, fallbackKey: string): string {
  const title =
    typeof schema === "object" && schema !== null
      ? (schema as { title?: unknown }).title
      : undefined;
  if (typeof title === "string" && title.trim().length > 0) {
    return sanitizeSchemaName(title);
  }

  return sanitizeSchemaName(fallbackKey.replace(/^def-/, "Schema"));
}

function sanitizeSchemaName(value: string): string {
  const parts = value
    .replace(/[^A-Za-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  const pascalCase = parts
    .map((part) => part[0]!.toUpperCase() + part.slice(1))
    .join("");

  if (pascalCase.length === 0) {
    return "Schema";
  }

  return /^[A-Za-z_]/.test(pascalCase) ? pascalCase : `Schema${pascalCase}`;
}

function reserveUniqueName(baseName: string, usedNames: Set<string>): string {
  let candidate = baseName;
  let suffix = 2;

  while (usedNames.has(candidate)) {
    candidate = `${baseName}${suffix}`;
    suffix += 1;
  }

  usedNames.add(candidate);
  return candidate;
}

function rewriteSchemaReferences<T>(
  value: T,
  renameMap: Map<string, string>,
): T {
  if (Array.isArray(value)) {
    return value.map((item) => rewriteSchemaReferences(item, renameMap)) as T;
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const rewritten: Record<string, unknown> = {};

  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (key === "$ref" && typeof entry === "string") {
      rewritten[key] = rewriteSchemaRef(entry, renameMap);
      continue;
    }

    rewritten[key] = rewriteSchemaReferences(entry, renameMap);
  }

  return rewritten as T;
}

function rewriteSchemaRef(ref: string, renameMap: Map<string, string>): string {
  if (!ref.startsWith(schemaRefPrefix)) {
    return ref;
  }

  const schemaName = ref.slice(schemaRefPrefix.length);
  const stableName = renameMap.get(schemaName);
  return stableName ? `${schemaRefPrefix}${stableName}` : ref;
}
