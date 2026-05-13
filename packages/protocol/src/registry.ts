import type {
  AgentDefinition,
  CapabilityToken,
  IdentityManifest,
  PrivateKeyMaterial,
  PublicKey,
  RevocationRecord,
  ServiceEndpoint,
  VerificationOutcome,
  WitnessReceipt,
} from "./types.js";
import type { RegistryBackend } from "./backend.js";
import type { RegistryEvent } from "./events.js";
import { createRegistryEventDraft } from "./events.js";
import {
  addAgent,
  addPublicKey,
  addService,
  createIdentityManifestDraft,
  signIdentityManifest,
  signIdentityManifestWithSignature,
  verifyIdentityManifest,
  createCapabilityTokenDraft,
  signCapabilityTokenWithSignature,
} from "./manifest.js";
import { verifyCapabilityToken } from "./capabilities.js";
import {
  createSignedRequestDraft,
  signSignedRequestDraft,
  verifySignedRequest,
} from "./request.js";
import { inferRootIdentityId, resolveIdentity } from "./resolver.js";
import type { SignedRequest } from "./types.js";
import { createMemoryWitnessService, type WitnessService } from "./witness.js";
import {
  createLocalDevKeyCustody,
  createMemoryKeyCustodyProvider,
  type KeyCustodyProvider,
} from "./custody.js";

function createPublicKeyMaterial(input: {
  id: string;
  publicKey: string;
  purpose: PublicKey["purpose"];
  createdAt: string;
  status?: PublicKey["status"];
}): PublicKey {
  return {
    id: input.id,
    type: "ed25519",
    publicKey: input.publicKey,
    purpose: input.purpose,
    status: input.status ?? "active",
    createdAt: input.createdAt,
  };
}

function createPrivateKeyMaterial(input: {
  id: string;
  publicKey: string;
  privateKey: string;
  purpose: PrivateKeyMaterial["purpose"];
  createdAt: string;
  status?: PrivateKeyMaterial["status"];
}): PrivateKeyMaterial {
  return {
    id: input.id,
    type: "ed25519",
    publicKey: input.publicKey,
    privateKey: input.privateKey,
    purpose: input.purpose,
    status: input.status ?? "active",
    createdAt: input.createdAt,
  };
}

export interface CreateIdentityResult {
  manifest: IdentityManifest;
  rootKey: PrivateKeyMaterial;
}

export interface RegisterAgentResult {
  manifest: IdentityManifest;
  agent: AgentDefinition;
  agentKey: PrivateKeyMaterial;
}

export class IdentityRegistry {
  constructor(
    private readonly backend: RegistryBackend,
    private readonly custody: KeyCustodyProvider = createMemoryKeyCustodyProvider(
      { recordStore: backend, allowPrivateKeyExport: true },
    ),
    private readonly witness: WitnessService = createMemoryWitnessService(),
  ) {}

  async createIdentity(id: string): Promise<CreateIdentityResult> {
    const existing = await this.backend.readManifest(id);
    if (existing) {
      throw new Error(`Identity already exists: ${id}`);
    }

    const now = new Date().toISOString();
    const rootPublicKey = await this.custody.provisionKey({
      identityId: id,
      keyId: "root",
      purpose: "root",
    });

    let rootPrivateKey = "";
    try {
      rootPrivateKey = await this.custody.exportPrivateKey({
        identityId: id,
        keyId: rootPublicKey.id,
      });
    } catch {
      /* export disabled — private key not available to caller */
    }

    const rootKey: PrivateKeyMaterial = {
      ...rootPublicKey,
      privateKey: rootPrivateKey,
    };

    const manifestDraft = createIdentityManifestDraft(
      id,
      createPublicKeyMaterial({
        id: rootPublicKey.id,
        publicKey: rootPublicKey.publicKey,
        purpose: rootPublicKey.purpose,
        createdAt: now,
      }),
      now,
    );
    const manifestSignature = await this.custody.sign({
      identityId: id,
      keyId: rootPublicKey.id,
      payload: manifestDraft,
    });
    const manifest = signIdentityManifestWithSignature(
      manifestDraft,
      manifestSignature,
    );

    await this.backend.writeManifest(manifest);
    await this.backend.writePrivateRecord({
      id,
      keys: { [rootKey.id]: rootKey },
      createdAt: now,
      updatedAt: now,
    });
    await this.recordEvent(id, "identity.created", id, rootPublicKey.id, {
      rootKeyId: rootPublicKey.id,
    });

    return { manifest, rootKey };
  }

  async getManifest(id: string): Promise<IdentityManifest | null> {
    return this.backend.readManifest(id);
  }

  async registerService(
    identityId: string,
    service: ServiceEndpoint,
  ): Promise<IdentityManifest> {
    const manifest = await this.requireManifest(identityId);

    if (manifest.services.some((entry) => entry.id === service.id)) {
      throw new Error(`Service already exists: ${service.id}`);
    }

    if (
      service.publicKeyId &&
      !manifest.publicKeys.some((key) => key.id === service.publicKeyId)
    ) {
      throw new Error(
        `Service references missing public key: ${service.publicKeyId}`,
      );
    }

    const updated = addService(manifest, service);
    const signed = await this.resign(identityId, updated);
    await this.backend.writeManifest(signed);
    await this.recordEvent(
      identityId,
      "service.added",
      service.id,
      signed.signatureKeyId,
      {
        endpoint: service.endpoint,
        type: service.type,
      },
    );

    return signed;
  }

  async registerAgent(
    identityId: string,
    agentInput: Omit<AgentDefinition, "owner" | "publicKeyId" | "status"> & {
      status?: AgentDefinition["status"] | undefined;
    },
  ): Promise<RegisterAgentResult> {
    const manifest = await this.requireManifest(identityId);

    if (manifest.agents.some((entry) => entry.id === agentInput.id)) {
      throw new Error(`Agent already exists: ${agentInput.id}`);
    }

    const agentKeyId = `${agentInput.id}#agent`;
    const now = new Date().toISOString();
    const agentPublicKey = await this.custody.provisionKey({
      identityId,
      keyId: agentKeyId,
      purpose: "agent",
    });
    let agentPrivateKey = "";
    try {
      agentPrivateKey = await this.custody.exportPrivateKey({
        identityId,
        keyId: agentKeyId,
      });
    } catch {
      /* export disabled */
    }
    const agentKey = createPrivateKeyMaterial({
      id: agentKeyId,
      publicKey: agentPublicKey.publicKey,
      privateKey: agentPrivateKey,
      purpose: "agent",
      createdAt: now,
    });

    const agent: AgentDefinition = {
      id: agentInput.id,
      owner: identityId,
      publicKeyId: agentKeyId,
      endpoint: agentInput.endpoint,
      allowedCapabilities: [...agentInput.allowedCapabilities].sort(),
      deniedCapabilities: [...agentInput.deniedCapabilities].sort(),
      auditLogEndpoint: agentInput.auditLogEndpoint,
      status: agentInput.status ?? "active",
      expiresAt: agentInput.expiresAt,
    };

    const updated = addAgent(
      addPublicKey(manifest, {
        id: agentKey.id,
        type: agentKey.type,
        publicKey: agentKey.publicKey,
        purpose: agentKey.purpose,
        status: agentKey.status,
        createdAt: now,
      }),
      agent,
    );
    const signed = await this.resign(identityId, updated);

    await this.backend.writeManifest(signed);

    // Persist agent key to PrivateIdentityRecord for cross-instance key lookup
    const existingRecord = await this.backend.readPrivateRecord(identityId);
    if (existingRecord) {
      await this.backend.writePrivateRecord({
        ...existingRecord,
        keys: { ...existingRecord.keys, [agentKey.id]: agentKey },
        updatedAt: now,
      });
    }

    await this.recordEvent(
      identityId,
      "key.added",
      agentKey.id,
      signed.signatureKeyId,
      {
        owner: identityId,
        purpose: agentKey.purpose,
        status: agentKey.status,
      },
    );

    await this.recordEvent(
      identityId,
      "agent.added",
      agent.id,
      signed.signatureKeyId,
      {
        publicKeyId: agent.publicKeyId,
        endpoint: agent.endpoint,
      },
    );

    return {
      manifest: signed,
      agent,
      agentKey,
    };
  }

  async issueCapabilityToken(
    identityId: string,
    input: {
      subject: string;
      permissions: string[];
      denied?: string[] | undefined;
      audience?: string | undefined;
      ttlSeconds?: number | undefined;
      nonce?: string | undefined;
      issuedAt?: Date | undefined;
    },
  ): Promise<CapabilityToken> {
    const manifest = await this.requireManifest(identityId);
    const permissions = [...new Set(input.permissions)].sort();
    const denied = input.denied ? [...new Set(input.denied)].sort() : undefined;

    const issuedAt = input.issuedAt ?? new Date();
    const expiresAt = new Date(
      issuedAt.getTime() + (input.ttlSeconds ?? 3600) * 1000,
    );
    const draft = createCapabilityTokenDraft({
      id: cryptoRandomId(),
      issuer: manifest.id,
      signatureKeyId: manifest.signatureKeyId,
      subject: input.subject,
      audience: input.audience,
      permissions,
      denied,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      nonce: input.nonce,
    });
    const signature = await this.custody.sign({
      identityId,
      keyId: manifest.signatureKeyId,
      payload: draft,
    });
    const token = signCapabilityTokenWithSignature(draft, signature);

    await this.recordEvent(
      identityId,
      "token.issued",
      token.id,
      manifest.signatureKeyId,
      {
        subject: token.subject,
        permissions: token.permissions,
        denied: token.denied,
        audience: token.audience,
      },
    );

    return token;
  }

  async resolve(name: string) {
    const rootId = inferRootIdentityId(name);
    const manifest = await this.backend.readManifest(rootId);
    return resolveIdentity(manifest, name);
  }

  async verifyCapability(
    identityId: string,
    token: CapabilityToken,
    permission: string,
    options: { expectedAudience?: string | undefined } = {},
  ): Promise<VerificationOutcome> {
    const manifest = await this.requireManifest(identityId);
    const revocations = await this.backend.readRevocationRecord(identityId);
    return verifyCapabilityToken(manifest, token, permission, new Date(), {
      expectedAudience: options.expectedAudience,
      revocations,
    });
  }

  async verifyRequest(
    identityId: string,
    request: SignedRequest,
    options: { body?: unknown; expectedAudience?: string | undefined } = {},
  ): Promise<VerificationOutcome> {
    const manifest = await this.requireManifest(identityId);
    const revocations = await this.backend.readRevocationRecord(identityId);
    return verifySignedRequest({
      manifest,
      request,
      body: options.body,
      expectedAudience: options.expectedAudience,
      replayStore: this.backend,
      revocations,
    });
  }

  async signRequest(
    identityId: string,
    input: {
      actor: string;
      issuer: string;
      capabilityToken: CapabilityToken;
      method: string;
      path: string;
      body?: unknown;
      nonce?: string | undefined;
      timestamp?: Date | undefined;
    },
  ): Promise<SignedRequest> {
    if (input.issuer !== identityId) {
      throw new Error(
        `Issuer mismatch: expected ${identityId}, got ${input.issuer}`,
      );
    }

    const manifest = await this.requireManifest(identityId);
    const agent = manifest.agents.find((entry) => entry.id === input.actor);
    if (!agent) {
      throw new Error(`Unknown agent: ${input.actor}`);
    }

    if (agent.status !== "active") {
      throw new Error(`Agent is not active: ${input.actor}`);
    }

    const draft = createSignedRequestDraft({
      actor: input.actor,
      issuer: input.issuer,
      signatureKeyId: agent.publicKeyId,
      capabilityToken: input.capabilityToken,
      method: input.method,
      path: input.path,
      body: input.body,
      nonce: input.nonce,
      timestamp: input.timestamp,
    });
    const signature = await this.custody.sign({
      identityId,
      keyId: agent.publicKeyId,
      payload: draft,
    });

    return signSignedRequestDraft(draft, signature);
  }

  async verifyManifest(identityId: string): Promise<VerificationOutcome> {
    const manifest = await this.requireManifest(identityId);
    return verifyIdentityManifest(manifest);
  }

  async listEvents(identityId: string): Promise<RegistryEvent[]> {
    return this.backend.listEvents(identityId);
  }

  async listWitnessReceipts(identityId: string): Promise<WitnessReceipt[]> {
    return this.backend.listWitnessReceipts(identityId);
  }

  async getRevocationState(
    identityId: string,
  ): Promise<RevocationRecord | null> {
    return this.backend.getRevocationState(identityId);
  }

  async listAllEvents(): Promise<RegistryEvent[]> {
    const ids = await this.backend.listIdentityIds();
    const perIdentity = await Promise.all(ids.map((id) => this.listEvents(id)));
    return perIdentity
      .flat()
      .sort(
        (a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      );
  }

  async revokeAgent(
    identityId: string,
    agentId: string,
    reason = "revoked by owner",
  ): Promise<IdentityManifest> {
    const manifest = await this.requireManifest(identityId);
    const agent = manifest.agents.find((entry) => entry.id === agentId);
    if (!agent) {
      throw new Error(`Unknown agent: ${agentId}`);
    }

    const now = new Date().toISOString();
    const nextManifest = {
      ...manifest,
      agents: manifest.agents.map((entry) =>
        entry.id === agentId
          ? {
              ...entry,
              status: "revoked" as const,
            }
          : entry,
      ),
      updatedAt: now,
    };

    const resigned = await this.resign(identityId, nextManifest);
    await this.backend.writeManifest(resigned);
    const event = await this.recordEvent(
      identityId,
      "agent.revoked",
      agentId,
      resigned.signatureKeyId,
      {
        publicKeyId: agent.publicKeyId,
        reason,
      },
    );
    await this.recordWitnessReceipt(identityId, event);

    return this.requireManifest(identityId);
  }

  async revokeCapabilityToken(
    identityId: string,
    tokenId: string,
    reason = "revoked by owner",
  ): Promise<IdentityManifest> {
    await this.requireManifest(identityId);
    const event = await this.recordEvent(
      identityId,
      "token.revoked",
      tokenId,
      await this.currentRootKeyId(identityId),
      {
        reason,
      },
    );
    await this.recordWitnessReceipt(identityId, event);

    return this.requireManifest(identityId);
  }

  async revokePublicKey(
    identityId: string,
    keyId: string,
    reason = "revoked by owner",
  ): Promise<IdentityManifest> {
    const manifest = await this.requireManifest(identityId);
    const key = manifest.publicKeys.find((entry) => entry.id === keyId);
    if (!key) {
      throw new Error(`Unknown public key: ${keyId}`);
    }

    const now = new Date().toISOString();
    const nextManifest = {
      ...manifest,
      publicKeys: manifest.publicKeys.map((entry) =>
        entry.id === keyId
          ? {
              ...entry,
              status: "revoked" as const,
              revokedAt: now,
              deactivatedAt: now,
            }
          : entry,
      ),
      updatedAt: now,
    };

    const resigned = await this.resign(identityId, nextManifest);

    await this.backend.writeManifest(resigned);
    const event = await this.recordEvent(
      identityId,
      "key.revoked",
      keyId,
      resigned.signatureKeyId,
      {
        reason,
      },
    );
    await this.recordWitnessReceipt(identityId, event);

    return resigned;
  }

  async rotateRootKey(
    identityId: string,
  ): Promise<{ manifest: IdentityManifest; newRootKey: PrivateKeyMaterial }> {
    const manifest = await this.requireManifest(identityId);
    const now = new Date().toISOString();
    const oldRoot = manifest.publicKeys.find(
      (entry) => entry.id === manifest.signatureKeyId,
    );
    if (!oldRoot) {
      throw new Error(`Missing root key for: ${identityId}`);
    }
    const newKeyId = `root-${Date.now()}`;
    const newRootPublicKey = await this.custody.provisionKey({
      identityId,
      keyId: newKeyId,
      purpose: "root",
    });
    let newRootPrivateKey = "";
    try {
      newRootPrivateKey = await this.custody.exportPrivateKey({
        identityId,
        keyId: newKeyId,
      });
    } catch {
      /* export disabled */
    }
    const newRootKey: PrivateKeyMaterial = {
      ...newRootPublicKey,
      privateKey: newRootPrivateKey,
    };

    const updatedManifest = {
      ...manifest,
      publicKeys: manifest.publicKeys.map((entry) =>
        entry.id === oldRoot.id
          ? {
              ...entry,
              status: "deprecated" as const,
              deactivatedAt: now,
            }
          : entry,
      ),
      updatedAt: now,
    };

    const withNewKey = addPublicKey(
      updatedManifest,
      createPublicKeyMaterial({
        id: newRootKey.id,
        publicKey: newRootKey.publicKey,
        purpose: "root",
        createdAt: now,
        status: "active",
      }),
    );

    const resignedDraft = {
      id: withNewKey.id,
      version: withNewKey.version,
      publicKeys: withNewKey.publicKeys,
      services: withNewKey.services,
      agents: withNewKey.agents,
      claims: withNewKey.claims,
      recovery: withNewKey.recovery,
      updatedAt: now,
      expiresAt: withNewKey.expiresAt,
      signatureKeyId: newRootKey.id,
    };
    const resigned = signIdentityManifestWithSignature(
      resignedDraft,
      await this.custody.sign({
        identityId,
        keyId: newRootKey.id,
        payload: resignedDraft,
      }),
    );

    await this.backend.writeManifest(resigned);
    await this.recordEvent(
      identityId,
      "key.deprecated",
      oldRoot.id,
      oldRoot.id,
      {
        replacementKeyId: newRootKey.id,
      },
    );
    await this.recordEvent(
      identityId,
      "key.added",
      newRootKey.id,
      newRootKey.id,
      {
        purpose: "root",
        status: newRootKey.status,
      },
    );
    await this.recordEvent(
      identityId,
      "identity.rotated",
      identityId,
      newRootKey.id,
      {
        oldRootKeyId: oldRoot.id,
        newRootKeyId: newRootKey.id,
      },
    );

    return {
      manifest: resigned,
      newRootKey,
    };
  }

  private async requireManifest(identityId: string): Promise<IdentityManifest> {
    const manifest = await this.backend.readManifest(identityId);
    if (!manifest) {
      throw new Error(`Unknown identity: ${identityId}`);
    }

    const verification = verifyIdentityManifest(manifest);
    if (!verification.ok) {
      throw new Error(verification.reason ?? "invalid_manifest_signature");
    }

    return manifest;
  }

  private async currentRootKeyId(identityId: string): Promise<string> {
    const manifest = await this.requireManifest(identityId);
    return manifest.signatureKeyId;
  }

  private async recordEvent(
    identityId: string,
    type: Parameters<typeof createRegistryEventDraft>[0]["type"],
    subjectId: string,
    signerKeyId: string,
    details?: Record<string, unknown> | undefined,
  ): Promise<RegistryEvent> {
    const events = await this.backend.listEvents(identityId);
    const previousHash = events.at(-1)?.hash ?? "genesis";
    const draft = createRegistryEventDraft({
      type,
      subjectId,
      signerKeyId,
      previousHash,
      details,
    });
    const signature = await this.custody.sign({
      identityId,
      keyId: signerKeyId,
      payload: draft,
    });

    return this.backend.appendEvent(identityId, { ...draft, signature });
  }

  private async recordWitnessReceipt(
    identityId: string,
    event: RegistryEvent,
  ): Promise<void> {
    if (!this.witness) {
      return;
    }

    if (
      event.type !== "agent.revoked" &&
      event.type !== "token.revoked" &&
      event.type !== "key.revoked"
    ) {
      return;
    }

    const currentReceipts = await this.backend.listWitnessReceipts(identityId);
    const receipt = await this.witness.issueReceipt(event, {
      identityId,
      logIndex: currentReceipts.length,
    });
    await this.backend.attachWitnessReceipt(identityId, receipt);
  }

  private async resign(
    identityId: string,
    manifest: IdentityManifest,
  ): Promise<IdentityManifest> {
    const signatureKeyId = manifest.signatureKeyId;
    const draft = {
      id: manifest.id,
      version: manifest.version,
      publicKeys: manifest.publicKeys,
      services: manifest.services,
      agents: manifest.agents,
      claims: manifest.claims,
      recovery: manifest.recovery,
      updatedAt: new Date().toISOString(),
      expiresAt: manifest.expiresAt,
      signatureKeyId,
    };

    return signIdentityManifestWithSignature(
      draft,
      await this.custody.sign({
        identityId,
        keyId: signatureKeyId,
        payload: draft,
      }),
    );
  }
}

function cryptoRandomId(): string {
  return `token-${Math.random().toString(16).slice(2)}-${Date.now().toString(16)}`;
}
