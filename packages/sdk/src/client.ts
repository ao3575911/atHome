import {
  createMutationAuthorization as protocolCreateMutationAuthorization,
  createSignedRequest as protocolCreateSignedRequest,
  serializeMutationAuthorization,
  type CapabilityToken,
  type IdentityManifest,
  type MutationAuthorization,
  type ServiceEndpoint,
  type SignedRequest,
  type VerificationOutcome,
} from "@home/protocol";

export interface ApiErrorResponse {
  ok: false;
  error: {
    code: string;
    message: string;
    details: Record<string, unknown>;
  };
}

export interface RootMutationSignerInput {
  identityId: string;
  keyId?: string;
  privateKey: string;
}

export interface MutationSigningRequest {
  method: string;
  path: string;
  body?: unknown;
}

export interface MutationSigner {
  signMutation(input: MutationSigningRequest): MutationAuthorization;
}

export type MutationAuthorizationInput = MutationAuthorization | MutationSigner;

export class HomeApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details: Record<string, unknown> = {},
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "HomeApiError";
  }
}

function isApiErrorResponse(payload: unknown): payload is ApiErrorResponse {
  return (
    typeof payload === "object" &&
    payload !== null &&
    "ok" in payload &&
    (payload as { ok?: unknown }).ok === false &&
    "error" in payload &&
    typeof (payload as { error?: unknown }).error === "object" &&
    (
      payload as {
        error?: { code?: unknown; message?: unknown; details?: unknown };
      }
    ).error !== undefined
  );
}

function stringifyBody(
  payload: string | URLSearchParams | FormData | Blob | ReadableStream | object,
): BodyInit {
  if (
    typeof payload === "string" ||
    payload instanceof URLSearchParams ||
    payload instanceof FormData ||
    payload instanceof Blob ||
    payload instanceof ReadableStream
  ) {
    return payload;
  }

  return JSON.stringify(payload);
}

function isMutationSigner(
  value: MutationAuthorizationInput,
): value is MutationSigner {
  return typeof (value as MutationSigner).signMutation === "function";
}

function mutationAuthorizationFor(
  authorization: MutationAuthorizationInput | undefined,
  input: MutationSigningRequest,
): MutationAuthorization | undefined {
  if (!authorization) {
    return undefined;
  }

  return isMutationSigner(authorization)
    ? authorization.signMutation(input)
    : authorization;
}

export function createRootMutationSigner(
  input: RootMutationSignerInput,
): MutationSigner {
  return {
    signMutation(request) {
      return protocolCreateMutationAuthorization({
        issuer: input.identityId,
        signatureKeyId: input.keyId ?? "root",
        method: request.method,
        path: request.path,
        body: request.body,
        privateKey: input.privateKey,
      });
    },
  };
}

export class HomeClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    const hasBody = init?.body !== undefined;
    const requestInit: RequestInit = { ...(init ?? {}) };

    if (hasBody) {
      requestInit.headers = {
        "content-type": "application/json",
        ...(init?.headers ?? {}),
      };
    }

    const response = await this.fetchImpl(
      `${this.baseUrl}${path}`,
      requestInit,
    );

    const text = await response.text();
    let payload: unknown;
    try {
      payload = text.length > 0 ? JSON.parse(text) : undefined;
    } catch {
      payload = text;
    }

    if (!response.ok) {
      if (isApiErrorResponse(payload)) {
        throw new HomeApiError(
          String(payload.error.code),
          String(payload.error.message),
          (payload.error.details ?? {}) as Record<string, unknown>,
          response.status,
        );
      }

      throw new HomeApiError(
        "request_failed",
        `Request failed with HTTP ${response.status}`,
        payload && typeof payload === "object"
          ? (payload as Record<string, unknown>)
          : {},
        response.status,
      );
    }

    return payload as T;
  }

  private withMutationAuthorization(
    init: RequestInit | undefined,
    authorization: MutationAuthorizationInput | undefined,
    input: MutationSigningRequest,
  ): RequestInit {
    const signedAuthorization = mutationAuthorizationFor(authorization, input);
    if (!signedAuthorization) {
      return init ?? {};
    }

    return {
      ...(init ?? {}),
      headers: {
        ...(init?.headers ?? {}),
        "x-home-authorization":
          serializeMutationAuthorization(signedAuthorization),
      },
    };
  }

  resolve(name: string): Promise<{
    ok: true;
    rootIdentity: IdentityManifest | null;
    resolvedType: "root" | "service" | "agent" | "unknown";
    resolvedEntry?:
      | ServiceEndpoint
      | { id: string; publicKeyId: string }
      | undefined;
    publicKey?:
      | {
          id: string;
          type: "ed25519";
          publicKey: string;
          purpose: "root" | "agent" | "recovery" | "signing";
        }
      | undefined;
    manifestSignatureValid: boolean;
  }> {
    return this.requestJson("/resolve", {
      method: "POST",
      body: stringifyBody({ name }),
    });
  }

  getIdentity(id: string): Promise<{ ok: true; manifest: IdentityManifest }> {
    return this.requestJson(`/identities/${encodeURIComponent(id)}`);
  }

  createIdentity(id: string): Promise<{
    ok: true;
    manifest: IdentityManifest;
    rootKeyId: string;
    privateKey?: string;
  }> {
    return this.requestJson("/identities", {
      method: "POST",
      body: stringifyBody({ id }),
    });
  }

  addService(
    identityId: string,
    service: ServiceEndpoint,
    authorization?: MutationAuthorizationInput,
  ): Promise<{ ok: true; manifest: IdentityManifest }> {
    const path = `/identities/${encodeURIComponent(identityId)}/services`;
    const method = "POST";

    return this.requestJson(path, {
      method,
      body: stringifyBody(service),
      ...this.withMutationAuthorization(undefined, authorization, {
        method,
        path,
        body: service,
      }),
    });
  }

  addAgent(
    identityId: string,
    agent: {
      id: string;
      allowedCapabilities: string[];
      deniedCapabilities: string[];
      endpoint?: string;
      auditLogEndpoint?: string;
      expiresAt?: string;
      status?: "active" | "revoked" | "suspended";
    },
    authorization?: MutationAuthorizationInput,
  ): Promise<{
    ok: true;
    manifest: IdentityManifest;
    agent: {
      id: string;
      owner: string;
      publicKeyId: string;
      status: "active" | "revoked" | "suspended";
    };
    privateKey?: string;
    publicKeyId: string;
  }> {
    const path = `/identities/${encodeURIComponent(identityId)}/agents`;
    const method = "POST";

    return this.requestJson(path, {
      method,
      body: stringifyBody(agent),
      ...this.withMutationAuthorization(undefined, authorization, {
        method,
        path,
        body: agent,
      }),
    });
  }

  issueCapabilityToken(
    identityId: string,
    input: {
      subject: string;
      permissions: string[];
      denied?: string[];
      audience?: string;
      ttlSeconds?: number;
      nonce?: string;
    },
    authorization?: MutationAuthorizationInput,
  ): Promise<{ ok: true; token: CapabilityToken; tokenId: string }> {
    const path = `/identities/${encodeURIComponent(identityId)}/capability-tokens`;
    const method = "POST";

    return this.requestJson(path, {
      method,
      body: stringifyBody(input),
      ...this.withMutationAuthorization(undefined, authorization, {
        method,
        path,
        body: input,
      }),
    });
  }

  revokeAgent(
    identityId: string,
    agentId: string,
    authorization?: MutationAuthorizationInput,
  ): Promise<{
    ok: true;
    revocation: {
      identityId: string;
      kind: "agent";
      id: string;
      revokedAt: string;
    };
  }> {
    const path = `/identities/${encodeURIComponent(identityId)}/agents/${encodeURIComponent(agentId)}/revoke`;
    const method = "POST";

    return this.requestJson(path, {
      method,
      ...this.withMutationAuthorization(undefined, authorization, {
        method,
        path,
      }),
    });
  }

  revokeCapabilityToken(
    identityId: string,
    tokenId: string,
    authorization?: MutationAuthorizationInput,
  ): Promise<{
    ok: true;
    revocation: {
      identityId: string;
      kind: "token";
      id: string;
      revokedAt: string;
    };
  }> {
    const path = `/identities/${encodeURIComponent(identityId)}/capability-tokens/${encodeURIComponent(tokenId)}/revoke`;
    const method = "POST";

    return this.requestJson(path, {
      method,
      ...this.withMutationAuthorization(undefined, authorization, {
        method,
        path,
      }),
    });
  }

  revokeKey(
    identityId: string,
    keyId: string,
    authorization?: MutationAuthorizationInput,
  ): Promise<{
    ok: true;
    revocation: {
      identityId: string;
      kind: "key";
      id: string;
      revokedAt: string;
    };
  }> {
    const path = `/identities/${encodeURIComponent(identityId)}/keys/${encodeURIComponent(keyId)}/revoke`;
    const method = "POST";

    return this.requestJson(path, {
      method,
      ...this.withMutationAuthorization(undefined, authorization, {
        method,
        path,
      }),
    });
  }

  verifyCapability(
    token: CapabilityToken,
    permission: string,
    expectedAudience?: string,
  ): Promise<{ ok: true; verification: VerificationOutcome }> {
    return this.requestJson("/verify/capability", {
      method: "POST",
      body: stringifyBody({ token, permission, expectedAudience }),
    });
  }

  verifyRequest(
    request: SignedRequest,
    body?: unknown,
    expectedAudience?: string,
  ): Promise<{ ok: true; verification: VerificationOutcome }> {
    return this.requestJson("/verify/request", {
      method: "POST",
      body: stringifyBody({ request, body, expectedAudience }),
    });
  }
}

export function createHomeClient(baseUrl: string): HomeClient {
  return new HomeClient(baseUrl);
}

export function createIdentity(client: HomeClient, id: string) {
  return client.createIdentity(id);
}

export function resolveName(client: HomeClient, name: string) {
  return client.resolve(name);
}

export function issueCapabilityToken(
  client: HomeClient,
  identityId: string,
  input: {
    subject: string;
    permissions: string[];
    denied?: string[];
    audience?: string;
    ttlSeconds?: number;
    nonce?: string;
  },
  authorization?: MutationAuthorizationInput,
) {
  return client.issueCapabilityToken(identityId, input, authorization);
}

export function revokeAgent(
  client: HomeClient,
  identityId: string,
  agentId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.revokeAgent(identityId, agentId, authorization);
}

export function revokeCapabilityToken(
  client: HomeClient,
  identityId: string,
  tokenId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.revokeCapabilityToken(identityId, tokenId, authorization);
}

export function revokeKey(
  client: HomeClient,
  identityId: string,
  keyId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.revokeKey(identityId, keyId, authorization);
}

export function verifyCapability(
  client: HomeClient,
  token: CapabilityToken,
  permission: string,
  expectedAudience?: string,
) {
  return client.verifyCapability(token, permission, expectedAudience);
}

export function verifySignedRequest(
  client: HomeClient,
  request: SignedRequest,
  body?: unknown,
  expectedAudience?: string,
) {
  return client.verifyRequest(request, body, expectedAudience);
}

export function createSignedRequest(
  input: Parameters<typeof protocolCreateSignedRequest>[0],
) {
  return protocolCreateSignedRequest(input);
}

export function createMutationAuthorization(
  input: Parameters<typeof protocolCreateMutationAuthorization>[0],
) {
  return protocolCreateMutationAuthorization(input);
}
