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
  type SignedRequestDraft,
  type VerificationOutcome,
  type WitnessReceipt,
} from "@athome/protocol";

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

export interface RequestSigningRequest {
  capabilityToken: CapabilityToken;
  method: string;
  path: string;
  body?: unknown;
  expectedAudience?: string;
}

export type MaybePromise<T> = T | Promise<T>;

export interface MutationSigner {
  signMutation(
    input: MutationSigningRequest,
  ): MaybePromise<MutationAuthorization>;
}

export interface RequestSigner {
  signRequest(input: RequestSigningRequest): MaybePromise<SignedRequest>;
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

export interface AgentRequestSignerInput {
  actor: string;
  issuer: string;
  signatureKeyId: string;
  privateKey: string;
}

export interface ExternalRequestSignerInput {
  actor: string;
  issuer: string;
  signatureKeyId: string;
  signDraft(draft: SignedRequestDraft): MaybePromise<string>;
  now?: () => Date;
  nonce?: () => string;
}

export interface KeyCustodyMetadata {
  mode: "browser-held" | "passkey" | "kms";
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

export class AtHomeApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details: Record<string, unknown> = {},
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "AtHomeApiError";
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

function createRootMutationSigner(
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

/**
 * DEV-ONLY: keeps a private key in memory and signs mutation drafts locally.
 */
export function createInMemoryMutationSigner(
  input: RootMutationSignerInput,
): MutationSigner {
  return createRootMutationSigner(input);
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

export function createInMemoryRequestSigner(
  input: AgentRequestSignerInput,
): RequestSigner {
  return {
    signRequest(request) {
      return protocolCreateSignedRequest({
        actor: input.actor,
        issuer: input.issuer,
        signatureKeyId: input.signatureKeyId,
        capabilityToken: request.capabilityToken,
        method: request.method.toUpperCase(),
        path: request.path,
        body: request.body,
        privateKey: input.privateKey,
      });
    },
  };
}

export function createExternalRequestSigner(
  input: ExternalRequestSignerInput,
): RequestSigner {
  return {
    async signRequest(request) {
      const timestamp = input.now?.() ?? new Date();
      const draft: SignedRequestDraft = {
        actor: input.actor,
        issuer: input.issuer,
        signatureKeyId: input.signatureKeyId,
        capabilityToken: request.capabilityToken,
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

export class AtHomeClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly defaultMutationAuthorization?: MutationAuthorizationInput,
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
      if (error instanceof AtHomeApiError) {
        throw error;
      }

      throw new AtHomeApiError(
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
        throw new AtHomeApiError(
          String(payload.error.code),
          String(payload.error.message),
          (payload.error.details ?? {}) as Record<string, unknown>,
          response.status,
        );
      }

      throw new AtHomeApiError(
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
    const candidate = authorization ?? this.defaultMutationAuthorization;
    if (!candidate) {
      throw new AtHomeApiError(
        "key_custody_required",
        "A mutation signer is required for this operation",
      );
    }

    const signedAuthorization = await mutationAuthorizationFor(
      candidate,
      input,
    );
    if (!signedAuthorization) {
      throw new AtHomeApiError(
        "key_custody_required",
        "A mutation signer is required for this operation",
      );
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

  async createIdentity(
    id: string,
    authorization?: MutationAuthorizationInput,
  ): Promise<{
    ok: true;
    manifest: IdentityManifest;
    rootKeyId: string;
    custody: KeyCustodyMetadata;
  }> {
    const path = "/identities";
    const method = "POST";
    const body = { id };

    return this.requestJson(
      path,
      await this.withMutationAuthorization(
        { method, body: stringifyBody(body) },
        authorization,
        {
          method,
          path,
          body,
        },
      ),
    );
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

  async suspendNamespace(
    identityId: string,
    input: { reason?: string } = {},
    authorization?: MutationAuthorizationInput,
  ): Promise<{ ok: true; manifest: IdentityManifest }> {
    const path = `/namespaces/${encodeURIComponent(identityId)}/suspend`;
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

  async restoreNamespace(
    identityId: string,
    input: { reason?: string } = {},
    authorization?: MutationAuthorizationInput,
  ): Promise<{ ok: true; manifest: IdentityManifest }> {
    const path = `/namespaces/${encodeURIComponent(identityId)}/restore`;
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

  async transferNamespace(
    identityId: string,
    input: { reason?: string } = {},
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
  }> {
    const path = `/namespaces/${encodeURIComponent(identityId)}/transfer`;
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

export function createAtHomeClient(
  baseUrl: string,
  fetchImpl?: typeof fetch,
  defaultMutationAuthorization?: MutationAuthorizationInput,
): AtHomeClient {
  return new AtHomeClient(
    baseUrl,
    fetchImpl ?? fetch,
    defaultMutationAuthorization,
  );
}

export function createIdentity(client: AtHomeClient, id: string) {
  return client.createIdentity(id);
}

export function getReadiness(client: AtHomeClient) {
  return client.getReadiness();
}

export function getStatus(client: AtHomeClient) {
  return client.getStatus();
}

export function resolveName(client: AtHomeClient, name: string) {
  return client.resolve(name);
}

export function listIdentityEvents(client: AtHomeClient, id: string) {
  return client.listIdentityEvents(id);
}

export function listWitnessReceipts(client: AtHomeClient, id: string) {
  return client.listWitnessReceipts(id);
}

export function getRevocationState(client: AtHomeClient, id: string) {
  return client.getRevocationState(id);
}

export function listAuditEvents(client: AtHomeClient) {
  return client.listAuditEvents();
}

export function issueCapabilityToken(
  client: AtHomeClient,
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
  client: AtHomeClient,
  identityId: string,
  agentId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.revokeAgent(identityId, agentId, authorization);
}

export function revokeCapabilityToken(
  client: AtHomeClient,
  identityId: string,
  tokenId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.revokeCapabilityToken(identityId, tokenId, authorization);
}

export function revokeKey(
  client: AtHomeClient,
  identityId: string,
  keyId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.revokeKey(identityId, keyId, authorization);
}

export function rotateRootKey(
  client: AtHomeClient,
  identityId: string,
  authorization?: MutationAuthorizationInput,
) {
  return client.rotateRootKey(identityId, authorization);
}

export function suspendNamespace(
  client: AtHomeClient,
  identityId: string,
  input: { reason?: string } = {},
  authorization?: MutationAuthorizationInput,
) {
  return client.suspendNamespace(identityId, input, authorization);
}

export function restoreNamespace(
  client: AtHomeClient,
  identityId: string,
  input: { reason?: string } = {},
  authorization?: MutationAuthorizationInput,
) {
  return client.restoreNamespace(identityId, input, authorization);
}

export function transferNamespace(
  client: AtHomeClient,
  identityId: string,
  input: { reason?: string } = {},
  authorization?: MutationAuthorizationInput,
) {
  return client.transferNamespace(identityId, input, authorization);
}

export function verifyCapability(
  client: AtHomeClient,
  token: CapabilityToken,
  permission: string,
  expectedAudience?: string,
) {
  return client.verifyCapability(token, permission, expectedAudience);
}

export function verifySignedRequest(
  client: AtHomeClient,
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
