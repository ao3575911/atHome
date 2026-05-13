import {
  createMutationAuthorization as protocolCreateMutationAuthorization,
  createSignedRequest as protocolCreateSignedRequest,
  hashBody,
  randomNonce,
  serializeMutationAuthorization,
  type CapabilityToken,
  type IdentityManifest,
  type MutationAuthorization,
  type MutationAuthorizationDraft,
  type RegistryEvent,
  type RevocationRecord,
  type ServiceEndpoint,
  type SignedRequest,
  type VerificationOutcome,
  type WitnessReceipt,
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

export type MaybePromise<T> = T | Promise<T>;

export interface MutationSigner {
  signMutation(
    input: MutationSigningRequest,
  ): MaybePromise<MutationAuthorization>;
}

export interface ExternalMutationSignerInput {
  identityId: string;
  keyId?: string;
  signDraft(draft: MutationAuthorizationDraft): MaybePromise<string>;
  now?: () => Date;
  nonce?: () => string;
}

export interface WebCryptoMutationSignerInput {
  identityId: string;
  keyId?: string;
  cryptoKey: CryptoKey;
  now?: () => Date;
  nonce?: () => string;
}

export interface KeyCustodyMetadata {
  mode: "local-dev-server-generated" | "local-dev-export";
  privateKeyExported: boolean;
  guidance: string;
}

export type MutationAuthorizationInput = MutationAuthorization | MutationSigner;

export interface ReadinessResponse {
  ok: true;
  [key: string]: unknown;
}

export interface StatusResponse {
  ok: true;
  status?: string;
  [key: string]: unknown;
}

export interface IdentityEventsResponse {
  ok: true;
  events: RegistryEvent[];
}

export interface WitnessReceiptsResponse {
  ok: true;
  receipts: WitnessReceipt[];
}

export interface RevocationStateResponse {
  ok: true;
  revocationState: RevocationRecord | null;
}

export interface AuditEventsResponse {
  ok: true;
  events: RegistryEvent[];
}

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

async function mutationAuthorizationFor(
  authorization: MutationAuthorizationInput | undefined,
  input: MutationSigningRequest,
): Promise<MutationAuthorization | undefined> {
  if (!authorization) {
    return undefined;
  }

  return isMutationSigner(authorization)
    ? await authorization.signMutation(input)
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

export function createExternalMutationSigner(
  input: ExternalMutationSignerInput,
): MutationSigner {
  return {
    async signMutation(request) {
      const timestamp = input.now?.() ?? new Date();
      const draft: MutationAuthorizationDraft = {
        issuer: input.identityId,
        signatureKeyId: input.keyId ?? "root",
        method: request.method.toUpperCase(),
        path: request.path,
        bodyHash: hashBody(request.body),
        timestamp: timestamp.toISOString(),
        nonce: input.nonce?.() ?? randomNonce(),
      };

      return {
        ...draft,
        signature: await input.signDraft(draft),
      };
    },
  };
}

export function createWebCryptoMutationSigner(
  input: WebCryptoMutationSignerInput,
): MutationSigner {
  return {
    async signMutation(request) {
      const timestamp = input.now?.() ?? new Date();
      const draft: MutationAuthorizationDraft = {
        issuer: input.identityId,
        signatureKeyId: input.keyId ?? "root",
        method: request.method.toUpperCase(),
        path: request.path,
        bodyHash: hashBody(request.body),
        timestamp: timestamp.toISOString(),
        nonce: input.nonce?.() ?? randomNonce(),
      };

      const canonical = JSON.stringify(draft);
      const encoded = new TextEncoder().encode(canonical);
      const sigBytes = await crypto.subtle.sign(
        { name: "Ed25519" },
        input.cryptoKey,
        encoded,
      );
      const signature = btoa(String.fromCharCode(...new Uint8Array(sigBytes)));

      return { ...draft, signature };
    },
  };
}

export class HomeClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  getReadiness(): Promise<ReadinessResponse> {
    return this.requestJson("/health");
  }

  getStatus(): Promise<StatusResponse> {
    return this.requestJson("/status");
  }

  private async requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    const hasBody = init?.body !== undefined;
    const requestInit: RequestInit = { ...(init ?? {}) };

    if (hasBody) {
      requestInit.headers = {
        "content-type": "application/json",
        ...(init?.headers ?? {}),
      };
    }

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, requestInit);
    } catch (error) {
      if (error instanceof HomeApiError) {
        throw error;
      }

      throw new HomeApiError(
        "network_error",
        error instanceof Error ? error.message : "Network request failed",
        {},
      );
    }

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

  private async withMutationAuthorization(
    init: RequestInit | undefined,
    authorization: MutationAuthorizationInput | undefined,
    input: MutationSigningRequest,
  ): Promise<RequestInit> {
    const signedAuthorization = await mutationAuthorizationFor(
      authorization,
      input,
    );
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

  listIdentityEvents(id: string): Promise<IdentityEventsResponse> {
    return this.requestJson(`/identities/${encodeURIComponent(id)}/events`);
  }

  listWitnessReceipts(id: string): Promise<WitnessReceiptsResponse> {
    return this.requestJson(
      `/identities/${encodeURIComponent(id)}/witness-receipts`,
    );
  }

  getRevocationState(id: string): Promise<RevocationStateResponse> {
    return this.requestJson(
      `/identities/${encodeURIComponent(id)}/revocation-state`,
    );
  }

  createIdentity(id: string): Promise<{
    ok: true;
    manifest: IdentityManifest;
    rootKeyId: string;
    custody: KeyCustodyMetadata;
    privateKey?: string;
  }> {
    return this.requestJson("/identities", {
      method: "POST",
      body: stringifyBody({ id }),
    });
  }

  async addService(
    identityId: string,
    service: ServiceEndpoint,
    authorization?: MutationAuthorizationInput,
  ): Promise<{ ok: true; manifest: IdentityManifest }> {
    const path = `/identities/${encodeURIComponent(identityId)}/services`;
    const method = "POST";

    return this.requestJson(
      path,
      await this.withMutationAuthorization(
        { method, body: stringifyBody(service) },
        authorization,
        {
          method,
          path,
          body: service,
        },
      ),
    );
  }

  async addAgent(
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
    custody: KeyCustodyMetadata;
  }> {
    const path = `/identities/${encodeURIComponent(identityId)}/agents`;
    const method = "POST";

    return this.requestJson(
      path,
      await this.withMutationAuthorization(
        { method, body: stringifyBody(agent) },
        authorization,
        {
          method,
          path,
          body: agent,
        },
      ),
    );
  }

  async issueCapabilityToken(
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

    return this.requestJson(
      path,
      await this.withMutationAuthorization(
        { method, body: stringifyBody(input) },
        authorization,
        {
          method,
          path,
          body: input,
        },
      ),
    );
  }

  async revokeAgent(
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

    return this.requestJson(
      path,
      await this.withMutationAuthorization({ method }, authorization, {
        method,
        path,
      }),
    );
  }

  async revokeCapabilityToken(
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

    return this.requestJson(
      path,
      await this.withMutationAuthorization({ method }, authorization, {
        method,
        path,
      }),
    );
  }

  async revokeKey(
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

    return this.requestJson(
      path,
      await this.withMutationAuthorization({ method }, authorization, {
        method,
        path,
      }),
    );
  }

  async rotateRootKey(
    identityId: string,
    authorization?: MutationAuthorizationInput,
  ): Promise<{
    ok: true;
    manifest: IdentityManifest;
    rootKeyId: string;
    rotated: {
      oldRootKeyId: string;
      newRootKeyId: string;
      rotatedAt: string;
    };
    custody: KeyCustodyMetadata;
    privateKey?: string;
  }> {
    const path = `/identities/${encodeURIComponent(identityId)}/keys/root/rotate`;
    const method = "POST";

    return this.requestJson(
      path,
      await this.withMutationAuthorization({ method }, authorization, {
        method,
        path,
      }),
    );
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

  listAuditEvents(): Promise<AuditEventsResponse> {
    return this.requestJson("/audit/events");
  }
}

export function createHomeClient(baseUrl: string): HomeClient {
  return new HomeClient(baseUrl);
}

export function createIdentity(client: HomeClient, id: string) {
  return client.createIdentity(id);
}

export function getReadiness(client: HomeClient) {
  return client.getReadiness();
}

export function getStatus(client: HomeClient) {
  return client.getStatus();
}

export function resolveName(client: HomeClient, name: string) {
  return client.resolve(name);
}

export function listIdentityEvents(client: HomeClient, id: string) {
  return client.listIdentityEvents(id);
}

export function listWitnessReceipts(client: HomeClient, id: string) {
  return client.listWitnessReceipts(id);
}

export function getRevocationState(client: HomeClient, id: string) {
  return client.getRevocationState(id);
}

export function listAuditEvents(client: HomeClient) {
  return client.listAuditEvents();
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

export function rotateRootKey(
  client: HomeClient,
  identityId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.rotateRootKey(identityId, authorization);
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
