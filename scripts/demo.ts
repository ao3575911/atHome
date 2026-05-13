import { join } from "node:path";
import {
  addAgent,
  addPublicKey,
  addService,
  derivePermission,
  generateEd25519KeyPair,
  hashBody,
  inferRootIdentityId,
  LocalJsonStore,
  randomNonce,
  signCanonicalPayload,
  type AgentDefinition,
  type CapabilityToken,
  type IdentityManifest,
  type IdentityManifestDraft,
  type Permission,
  type PrivateIdentityRecord,
  type PrivateKeyMaterial,
  type PublicKey,
  type ServiceEndpoint,
  type SignedRequest,
  type SignedRequestDraft,
  type VerificationOutcome,
  verifyCanonicalPayload,
} from "@athome/protocol";

type DemoResolvedIdentity = {
  rootIdentity: IdentityManifest | null;
  resolvedType: "root" | "service" | "agent" | "unknown";
  resolvedEntry?:
    | ServiceEndpoint
    | { id: string; publicKeyId: string }
    | undefined;
  publicKey?: PublicKey | undefined;
  manifestSignatureValid: boolean;
};

function findPublicKey(
  manifest: IdentityManifest,
  keyId: string,
): PublicKey | undefined {
  return manifest.publicKeys.find((key) => key.id === keyId);
}

function nowIso(): string {
  return new Date().toISOString();
}

function buildRootPublicKey(
  keyPair: ReturnType<typeof generateEd25519KeyPair>,
  createdAt: string,
): PrivateKeyMaterial {
  return {
    id: "root",
    type: "ed25519",
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    purpose: "root",
    status: "active",
    createdAt,
  };
}

function buildAgentPublicKey(
  agentId: string,
  keyPair: ReturnType<typeof generateEd25519KeyPair>,
  createdAt: string,
): PrivateKeyMaterial {
  return {
    id: `${agentId}#agent`,
    type: "ed25519",
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    purpose: "agent",
    status: "active",
    createdAt,
  };
}

function signManifest(
  manifest: IdentityManifestDraft | IdentityManifest,
  rootPrivateKey: string,
): IdentityManifest {
  const draft =
    "signature" in manifest
      ? (({ signature: _signature, ...rest }) => rest)(manifest)
      : manifest;
  return {
    ...(draft as IdentityManifestDraft),
    signature: signCanonicalPayload(draft, rootPrivateKey),
  };
}

function signCapabilityToken(input: {
  id: string;
  issuer: string;
  signatureKeyId: string;
  subject: string;
  permissions: Permission[];
  denied?: Permission[] | undefined;
  audience?: string | undefined;
  issuedAt: string;
  expiresAt: string;
  nonce?: string | undefined;
  privateKey: string;
}): CapabilityToken {
  const draft = {
    id: input.id,
    issuer: input.issuer,
    signatureKeyId: input.signatureKeyId,
    subject: input.subject,
    permissions: [...new Set(input.permissions)].sort(),
    denied: input.denied ? [...new Set(input.denied)].sort() : undefined,
    audience: input.audience,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };

  return {
    ...draft,
    signature: signCanonicalPayload(draft, input.privateKey),
  };
}

function signRequest(input: {
  actor: string;
  issuer: string;
  signatureKeyId: string;
  capabilityToken: CapabilityToken;
  method: string;
  path: string;
  body?: unknown;
  privateKey: string;
  timestamp?: Date | undefined;
  nonce?: string | undefined;
}): SignedRequest {
  const timestamp = input.timestamp ?? new Date();
  const draft: SignedRequestDraft = {
    actor: input.actor,
    issuer: input.issuer,
    signatureKeyId: input.signatureKeyId,
    capabilityToken: input.capabilityToken,
    method: input.method,
    path: input.path,
    bodyHash: hashBody(input.body),
    timestamp: timestamp.toISOString(),
    nonce: input.nonce ?? randomNonce(),
  };

  return {
    ...draft,
    signature: signCanonicalPayload(draft, input.privateKey),
  };
}

async function bootstrapIdentity(
  store: LocalJsonStore,
  id: string,
): Promise<{
  manifest: IdentityManifest;
  rootKey: PrivateKeyMaterial;
}> {
  const createdAt = nowIso();
  const rootKey = buildRootPublicKey(generateEd25519KeyPair(), createdAt);
  const manifestDraft: IdentityManifestDraft = {
    id,
    version: "1.0.0",
    publicKeys: [rootKey],
    services: [],
    agents: [],
    claims: [],
    updatedAt: createdAt,
    signatureKeyId: rootKey.id,
  };
  const manifest = signManifest(manifestDraft, rootKey.privateKey);
  const record: PrivateIdentityRecord = {
    id,
    keys: { [rootKey.id]: rootKey },
    createdAt,
    updatedAt: createdAt,
  };

  await store.writeManifest(manifest);
  await store.writePrivateRecord(record);

  return { manifest, rootKey };
}

async function persistManifest(
  store: LocalJsonStore,
  manifest: IdentityManifest,
): Promise<void> {
  await store.writeManifest(manifest);
}

async function registerService(
  store: LocalJsonStore,
  identityId: string,
  service: ServiceEndpoint,
  rootPrivateKey: string,
): Promise<IdentityManifest> {
  const current = await requireManifest(store, identityId);
  const updated = addService(current, service);
  const signed = signManifest(updated, rootPrivateKey);
  await persistManifest(store, signed);
  return signed;
}

async function registerAgent(
  store: LocalJsonStore,
  identityId: string,
  input: {
    id: string;
    allowedCapabilities: Permission[];
    deniedCapabilities: Permission[];
    endpoint?: string | undefined;
    auditLogEndpoint?: string | undefined;
  },
  rootPrivateKey: string,
): Promise<{
  manifest: IdentityManifest;
  agent: AgentDefinition;
  agentKey: PrivateKeyMaterial;
}> {
  const current = await requireManifest(store, identityId);
  const record = (await store.readPrivateRecord(identityId)) ?? {
    id: identityId,
    keys: {},
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  const createdAt = nowIso();
  const agentKey = buildAgentPublicKey(
    input.id,
    generateEd25519KeyPair(),
    createdAt,
  );
  const agent: AgentDefinition = {
    id: input.id,
    owner: identityId,
    publicKeyId: agentKey.id,
    endpoint: input.endpoint,
    allowedCapabilities: [...new Set(input.allowedCapabilities)].sort(),
    deniedCapabilities: [...new Set(input.deniedCapabilities)].sort(),
    auditLogEndpoint: input.auditLogEndpoint,
    status: "active",
  };
  const updated = addAgent(
    addPublicKey(current, {
      id: agentKey.id,
      type: agentKey.type,
      publicKey: agentKey.publicKey,
      purpose: agentKey.purpose,
      status: agentKey.status,
      createdAt: agentKey.createdAt,
    }),
    agent,
  );
  const signed = signManifest(updated, rootPrivateKey);

  record.keys[agentKey.id] = agentKey;
  record.updatedAt = createdAt;

  await persistManifest(store, signed);
  await store.writePrivateRecord(record);

  return { manifest: signed, agent, agentKey };
}

async function issueCapabilityToken(
  manifest: IdentityManifest,
  rootPrivateKey: string,
  input: {
    subject: string;
    permissions: Permission[];
    denied?: Permission[] | undefined;
    audience?: string | undefined;
    ttlSeconds?: number | undefined;
    nonce?: string | undefined;
  },
): Promise<CapabilityToken> {
  const agent = manifest.agents.find((entry) => entry.id === input.subject);
  if (!agent) {
    throw new Error(`Unknown agent ${input.subject}`);
  }

  const permissions = [...new Set(input.permissions)].sort();
  const denied = input.denied ? [...new Set(input.denied)].sort() : undefined;

  for (const permission of permissions) {
    if (!agent.allowedCapabilities.includes(permission)) {
      throw new Error(`Permission not allowed for agent: ${permission}`);
    }

    if (agent.deniedCapabilities.includes(permission)) {
      throw new Error(`Permission denied for agent: ${permission}`);
    }
  }

  for (const permission of denied ?? []) {
    if (permissions.includes(permission)) {
      throw new Error(
        `Capability token cannot both allow and deny: ${permission}`,
      );
    }
  }

  const issuedAt = new Date();
  const expiresAt = new Date(
    issuedAt.getTime() + (input.ttlSeconds ?? 3600) * 1000,
  );

  return signCapabilityToken({
    id: randomNonce(8),
    issuer: manifest.id,
    signatureKeyId: manifest.signatureKeyId,
    subject: input.subject,
    permissions,
    denied,
    audience: input.audience,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    nonce: input.nonce,
    privateKey: rootPrivateKey,
  });
}

function verifyManifest(manifest: IdentityManifest): VerificationOutcome {
  const draft: IdentityManifestDraft = {
    id: manifest.id,
    version: manifest.version,
    publicKeys: manifest.publicKeys,
    services: manifest.services,
    agents: manifest.agents,
    claims: manifest.claims,
    recovery: manifest.recovery,
    updatedAt: manifest.updatedAt,
    expiresAt: manifest.expiresAt,
    signatureKeyId: manifest.signatureKeyId,
  };

  const key = findPublicKey(manifest, manifest.signatureKeyId);
  if (!key) {
    return {
      ok: false,
      code: "missing_root_key",
      reason: `Signature key not found: ${manifest.signatureKeyId}`,
    };
  }

  if (key.status === "revoked") {
    return {
      ok: false,
      code: "key_revoked",
      reason: `Signature key revoked: ${manifest.signatureKeyId}`,
    };
  }

  if (key.status === "deprecated") {
    return {
      ok: false,
      code: "key_deprecated",
      reason: `Signature key deprecated: ${manifest.signatureKeyId}`,
    };
  }

  if (!verifyCanonicalPayload(draft, manifest.signature, key.publicKey)) {
    return {
      ok: false,
      code: "invalid_manifest_signature",
      reason: "Manifest signature verification failed",
    };
  }

  return { ok: true };
}

function verifyCapabilityToken(
  manifest: IdentityManifest,
  token: CapabilityToken,
  requestedPermission?: string,
  now = new Date(),
  revokedTokenIds = new Set<string>(),
): VerificationOutcome {
  if (token.issuer !== manifest.id) {
    return {
      ok: false,
      code: "token_issuer_mismatch",
      reason: "Capability token issuer does not match the manifest owner",
    };
  }

  const key = findPublicKey(manifest, token.signatureKeyId);
  if (!key) {
    return {
      ok: false,
      code: "key_not_found",
      reason: `Signature key not found: ${token.signatureKeyId}`,
    };
  }

  if (key.status === "revoked") {
    return {
      ok: false,
      code: "key_revoked",
      reason: `Signature key revoked: ${token.signatureKeyId}`,
    };
  }

  const draft = {
    id: token.id,
    issuer: token.issuer,
    signatureKeyId: token.signatureKeyId,
    subject: token.subject,
    audience: token.audience,
    permissions: token.permissions,
    denied: token.denied,
    issuedAt: token.issuedAt,
    expiresAt: token.expiresAt,
    nonce: token.nonce,
  };

  if (!verifyCanonicalPayload(draft, token.signature, key.publicKey)) {
    return {
      ok: false,
      code: "token_signature_invalid",
      reason: "Capability token signature verification failed",
    };
  }

  const issuedAt = Date.parse(token.issuedAt);
  const expiresAt = Date.parse(token.expiresAt);
  const current = now.getTime();

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
    return {
      ok: false,
      code: "invalid_token_timestamps",
      reason: "Capability token timestamps are invalid",
    };
  }

  if (issuedAt > current + 5 * 60 * 1000) {
    return {
      ok: false,
      code: "token_issued_in_future",
      reason: "Capability token was issued in the future",
    };
  }

  if (expiresAt <= current) {
    return {
      ok: false,
      code: "token_expired",
      reason: "Capability token expired",
    };
  }

  const agent = manifest.agents.find((entry) => entry.id === token.subject);
  if (!agent) {
    return {
      ok: false,
      code: "token_subject_not_registered",
      reason: `Token subject not registered: ${token.subject}`,
    };
  }

  if (agent.status === "revoked") {
    return {
      ok: false,
      code: "agent_revoked",
      reason: `Agent revoked: ${token.subject}`,
    };
  }

  if (agent.status === "suspended") {
    return {
      ok: false,
      code: "agent_suspended",
      reason: `Agent suspended: ${token.subject}`,
    };
  }

  if (agent.expiresAt && Date.parse(agent.expiresAt) <= current) {
    return {
      ok: false,
      code: "agent_expired",
      reason: `Agent expired: ${token.subject}`,
    };
  }

  if (requestedPermission) {
    if (!token.permissions.includes(requestedPermission)) {
      return {
        ok: false,
        code: "permission_not_granted",
        reason: `Requested permission ${requestedPermission} is not granted to ${token.subject}`,
      };
    }

    if (token.denied?.includes(requestedPermission)) {
      return {
        ok: false,
        code: "permission_denied",
        reason: `Requested permission ${requestedPermission} is explicitly denied by the token`,
      };
    }

    if (!agent.allowedCapabilities.includes(requestedPermission)) {
      return {
        ok: false,
        code: "permission_not_granted",
        reason: `Requested permission ${requestedPermission} is not allowed for ${token.subject}`,
      };
    }

    if (agent.deniedCapabilities.includes(requestedPermission)) {
      return {
        ok: false,
        code: "permission_denied",
        reason: `Requested permission ${requestedPermission} is explicitly denied for ${token.subject}`,
      };
    }
  }

  const tokenId = token.id ?? token.nonce ?? token.signature;
  if (revokedTokenIds.has(tokenId)) {
    return {
      ok: false,
      code: "token_revoked",
      reason: `Capability token revoked: ${tokenId}`,
    };
  }

  return {
    ok: true,
    details: {
      tokenId,
      requestedPermission,
    },
  };
}

function verifyRequestTime(timestamp: string, now: Date): VerificationOutcome {
  const parsed = Date.parse(timestamp);

  if (Number.isNaN(parsed)) {
    return {
      ok: false,
      code: "invalid_request_timestamp",
      reason: "Request timestamp is invalid",
    };
  }

  const delta = Math.abs(now.getTime() - parsed);
  if (delta > 5 * 60 * 1000) {
    return {
      ok: false,
      code: "request_timestamp_out_of_window",
      reason: "Request timestamp is out of window",
    };
  }

  return { ok: true };
}

async function verifyRequest(
  manifest: IdentityManifest,
  request: SignedRequest,
  body: unknown,
  opts: {
    expectedAudience?: string;
    revokedTokenIds?: Set<string>;
    now?: Date;
    useReplayProtection?: boolean;
  } = {},
): Promise<VerificationOutcome> {
  const now = opts.now ?? new Date();
  const manifestVerification = verifyManifest(manifest);
  if (!manifestVerification.ok) {
    return manifestVerification;
  }

  if (request.issuer !== manifest.id) {
    return {
      ok: false,
      code: "request_issuer_mismatch",
      reason: "Signed request issuer does not match manifest owner",
    };
  }

  const agent = manifest.agents.find((entry) => entry.id === request.actor);
  if (!agent) {
    return {
      ok: false,
      code: "request_actor_not_registered",
      reason: `Request actor not registered: ${request.actor}`,
    };
  }

  if (agent.status === "revoked") {
    return {
      ok: false,
      code: "agent_revoked",
      reason: `Agent revoked: ${request.actor}`,
    };
  }

  if (agent.status === "suspended") {
    return {
      ok: false,
      code: "agent_suspended",
      reason: `Agent suspended: ${request.actor}`,
    };
  }

  if (agent.expiresAt && Date.parse(agent.expiresAt) <= now.getTime()) {
    return {
      ok: false,
      code: "agent_expired",
      reason: `Agent expired: ${request.actor}`,
    };
  }

  const requestedPermission = derivePermission(request.method, request.path);
  const tokenCheck = verifyCapabilityToken(
    manifest,
    request.capabilityToken,
    requestedPermission,
    now,
    opts.revokedTokenIds ?? new Set(),
  );
  if (!tokenCheck.ok) {
    return tokenCheck;
  }

  if (opts.expectedAudience) {
    if (!request.capabilityToken.audience) {
      return {
        ok: false,
        code: "audience_required",
        reason: `Capability token requires audience ${opts.expectedAudience}`,
      };
    }

    if (request.capabilityToken.audience !== opts.expectedAudience) {
      return {
        ok: false,
        code: "audience_mismatch",
        reason: `Capability token audience ${request.capabilityToken.audience} does not match ${opts.expectedAudience}`,
      };
    }
  }

  const publicKey = findPublicKey(manifest, agent.publicKeyId);
  if (!publicKey) {
    return {
      ok: false,
      code: "key_not_found",
      reason: `Agent public key not found: ${agent.publicKeyId}`,
    };
  }

  const draft: SignedRequestDraft = {
    actor: request.actor,
    issuer: request.issuer,
    signatureKeyId: request.signatureKeyId,
    capabilityToken: request.capabilityToken,
    method: request.method,
    path: request.path,
    bodyHash: request.bodyHash,
    timestamp: request.timestamp,
    nonce: request.nonce,
  };

  if (!verifyCanonicalPayload(draft, request.signature, publicKey.publicKey)) {
    return {
      ok: false,
      code: "invalid_request_signature",
      reason: "Signed request signature verification failed",
    };
  }

  const timestampVerification = verifyRequestTime(request.timestamp, now);
  if (!timestampVerification.ok) {
    return timestampVerification;
  }

  if (body !== undefined) {
    const expectedHash = hashBody(body);
    if (expectedHash !== request.bodyHash) {
      return {
        ok: false,
        code: "body_hash_mismatch",
        reason: "Request body hash does not match the provided body",
      };
    }
  } else if (request.bodyHash.length !== 64) {
    return {
      ok: false,
      code: "invalid_body_hash",
      reason: "Request body hash is invalid",
    };
  }

  if (opts.useReplayProtection !== false) {
    if (await optsNowHasNonce(manifest.id, request.nonce)) {
      return {
        ok: false,
        code: "nonce_replayed",
        reason: "Request nonce was already used",
      };
    }
    await optsRecordNonce(
      manifest.id,
      request.nonce,
      now.getTime() + 5 * 60 * 1000,
    );
  }

  return {
    ok: true,
    details: {
      requestedPermission,
      actor: request.actor,
      audience: request.capabilityToken.audience ?? null,
      tokenId: request.capabilityToken.id,
    },
  };
}

let replayStore: LocalJsonStore | null = null;
async function optsNowHasNonce(scope: string, nonce: string): Promise<boolean> {
  if (!replayStore) {
    return false;
  }

  return replayStore.hasNonce(scope, nonce);
}

async function optsRecordNonce(
  scope: string,
  nonce: string,
  expiresAtMs: number,
): Promise<void> {
  if (!replayStore) {
    return;
  }

  await replayStore.recordNonce(
    scope,
    nonce,
    new Date(expiresAtMs).toISOString(),
  );
}

async function requireManifest(
  store: LocalJsonStore,
  id: string,
): Promise<IdentityManifest> {
  const manifest = await store.readManifest(id);
  if (!manifest) {
    throw new Error(`Unknown identity: ${id}`);
  }

  return manifest;
}

async function resolveIdentity(
  store: LocalJsonStore,
  name: string,
): Promise<DemoResolvedIdentity> {
  const rootId = inferRootIdentityId(name);
  const manifest = await store.readManifest(rootId);

  if (!manifest) {
    return {
      rootIdentity: null,
      resolvedType: "unknown",
      manifestSignatureValid: false,
    };
  }

  const manifestSignatureValid = verifyManifest(manifest).ok;
  if (name === manifest.id) {
    return {
      rootIdentity: manifest,
      resolvedType: "root",
      publicKey: findPublicKey(manifest, manifest.signatureKeyId),
      manifestSignatureValid,
    };
  }

  const service = manifest.services.find((entry) => entry.id === name);
  if (service) {
    return {
      rootIdentity: manifest,
      resolvedType: "service",
      resolvedEntry: service,
      publicKey: service.publicKeyId
        ? findPublicKey(manifest, service.publicKeyId)
        : findPublicKey(manifest, manifest.signatureKeyId),
      manifestSignatureValid,
    };
  }

  const agent = manifest.agents.find((entry) => entry.id === name);
  if (agent) {
    return {
      rootIdentity: manifest,
      resolvedType: "agent",
      resolvedEntry: { id: agent.id, publicKeyId: agent.publicKeyId },
      publicKey: findPublicKey(manifest, agent.publicKeyId),
      manifestSignatureValid,
    };
  }

  return {
    rootIdentity: manifest,
    resolvedType: "unknown",
    manifestSignatureValid,
  };
}

export async function runDemo(): Promise<void> {
  const store = new LocalJsonStore(join(process.cwd(), "data"));
  replayStore = store;
  await store.removeIdentity("krav@atHome");
  await store.removeIdentity("alice@atHome");

  const root = await bootstrapIdentity(store, "krav@atHome");
  const rootManifest = await requireManifest(store, "krav@atHome");
  const withService = await registerService(
    store,
    "krav@atHome",
    {
      id: "agent@krav",
      type: "agent",
      endpoint: "https://demo.local/agent",
    },
    root.rootKey.privateKey,
  );
  const withAgent = await registerAgent(
    store,
    "krav@atHome",
    {
      id: "foreman@krav",
      allowedCapabilities: ["profile:read", "email:draft", "logs:analyze"],
      deniedCapabilities: ["payment:send", "vault:delete", "social:post"],
      endpoint: "https://demo.local/foreman",
      auditLogEndpoint: "https://demo.local/audit",
    },
    root.rootKey.privateKey,
  );

  const token = await issueCapabilityToken(
    withAgent.manifest,
    root.rootKey.privateKey,
    {
      subject: "foreman@krav",
      permissions: ["profile:read", "email:draft", "logs:analyze"],
      denied: ["payment:send", "vault:delete", "social:post"],
      ttlSeconds: 3600,
      nonce: randomNonce(),
    },
  );

  const successRequest = signRequest({
    actor: "foreman@krav",
    issuer: "krav@atHome",
    signatureKeyId: withAgent.agent.publicKeyId,
    capabilityToken: token,
    method: "POST",
    path: "/emails/draft",
    body: {
      subject: "Hello from the demo",
      message: "Please draft this message.",
    },
    privateKey: withAgent.agentKey.privateKey,
  });

  const successVerification = await verifyRequest(
    withAgent.manifest,
    successRequest,
    {
      subject: "Hello from the demo",
      message: "Please draft this message.",
    },
  );

  const deniedRequest = signRequest({
    actor: "foreman@krav",
    issuer: "krav@atHome",
    signatureKeyId: withAgent.agent.publicKeyId,
    capabilityToken: token,
    method: "POST",
    path: "/payments/send",
    body: { amount: 25, currency: "USD" },
    privateKey: withAgent.agentKey.privateKey,
  });

  const deniedVerification = await verifyRequest(
    withAgent.manifest,
    deniedRequest,
    {
      amount: 25,
      currency: "USD",
    },
  );

  const resolution = await resolveIdentity(store, "agent@krav");

  const aliceIdentity = await bootstrapIdentity(store, "alice@atHome");
  const aliceWithServices = await registerService(
    store,
    "alice@atHome",
    {
      id: "inbox@alice",
      type: "inbox",
      endpoint: "https://demo.local/inbox",
    },
    aliceIdentity.rootKey.privateKey,
  );
  const aliceWithVault = await registerService(
    store,
    "alice@atHome",
    {
      id: "vault@alice",
      type: "vault",
      endpoint: "https://demo.local/vault",
    },
    aliceIdentity.rootKey.privateKey,
  );
  const aliceAgent = await registerAgent(
    store,
    "alice@atHome",
    {
      id: "assistant@alice",
      allowedCapabilities: ["email:draft", "profile:read"],
      deniedCapabilities: ["vault:delete", "payment:send"],
      endpoint: "https://demo.local/assistant",
      auditLogEndpoint: "https://demo.local/audit",
    },
    aliceIdentity.rootKey.privateKey,
  );

  const aliceToken = await issueCapabilityToken(
    aliceAgent.manifest,
    aliceIdentity.rootKey.privateKey,
    {
      subject: "assistant@alice",
      permissions: ["email:draft"],
      denied: ["vault:delete"],
      audience: "inbox@alice",
      ttlSeconds: 3600,
      nonce: "alice-inbox-token-1",
    },
  );

  const inboxRequest = signRequest({
    actor: "assistant@alice",
    issuer: "alice@atHome",
    signatureKeyId: aliceAgent.agent.publicKeyId,
    capabilityToken: aliceToken,
    method: "POST",
    path: "/inbox/messages",
    body: {
      subject: "Welcome",
      message: "Please route this message to Alice inbox.",
    },
    privateKey: aliceAgent.agentKey.privateKey,
    nonce: "alice-inbox-request-1",
  });

  const inboxVerification = await verifyRequest(
    aliceAgent.manifest,
    inboxRequest,
    {
      subject: "Welcome",
      message: "Please route this message to Alice inbox.",
    },
    { expectedAudience: "inbox@alice", useReplayProtection: false },
  );

  const vaultMismatchVerification = await verifyRequest(
    aliceAgent.manifest,
    inboxRequest,
    {
      subject: "Welcome",
      message: "Please route this message to Alice inbox.",
    },
    { expectedAudience: "vault@alice", useReplayProtection: false },
  );

  const revokedTokenVerification = await verifyRequest(
    aliceAgent.manifest,
    inboxRequest,
    {
      subject: "Welcome",
      message: "Please route this message to Alice inbox.",
    },
    {
      expectedAudience: "inbox@alice",
      useReplayProtection: false,
      revokedTokenIds: new Set([aliceToken.id]),
    },
  );

  console.log(
    JSON.stringify(
      {
        v0_2: {
          identity: rootManifest.id,
          rootKeyId: rootManifest.signatureKeyId,
          agent: withAgent.agent.id,
          agentKeyId: withAgent.agent.publicKeyId,
          tokenIssuedFor: token.subject,
          successRequestHash: hashBody({
            subject: "Hello from the demo",
            message: "Please draft this message.",
          }),
          successVerification,
          deniedVerification,
          resolution,
        },
        aliceScenario: {
          identity: aliceWithServices.id,
          agent: aliceAgent.agent.id,
          tokenAudience: aliceToken.audience,
          tokenId: aliceToken.id,
          inboxVerification,
          vaultMismatchVerification,
          revokedTokenVerification,
          note: "Audience and revocation are enforced by the protocol package itself; the demo now exercises the live verification path instead of emulating policy locally.",
        },
      },
      null,
      2,
    ),
  );
}

if (import.meta.main) {
  runDemo().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
