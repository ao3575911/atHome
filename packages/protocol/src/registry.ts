import type {
  AgentDefinition,
  CapabilityToken,
  IdentityManifest,
  PrivateIdentityRecord,
  PrivateKeyMaterial,
  PublicKey,
  ServiceEndpoint,
  VerificationOutcome,
} from "./types.js";
import { generateEd25519KeyPair, randomNonce } from "./crypto.js";
import type { RegistryBackend } from "./backend.js";
import type { RegistryEvent } from "./events.js";
import { createRegistryEventDraft, signRegistryEvent } from "./events.js";
import {
  addAgent,
  addPublicKey,
  addService,
  createIdentityManifestDraft,
  signIdentityManifest,
  verifyIdentityManifest,
} from "./manifest.js";
import { issueCapabilityToken, verifyCapabilityToken } from "./capabilities.js";
import { createSignedRequest, verifySignedRequest } from "./request.js";
import { inferRootIdentityId, resolveIdentity } from "./resolver.js";
import type { SignedRequest } from "./types.js";
import { createMemoryWitnessService, type WitnessService } from "./witness.js";

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
    private readonly witness: WitnessService = createMemoryWitnessService(),
  ) {}

  async createIdentity(id: string): Promise<CreateIdentityResult> {
    const existing = await this.backend.readManifest(id);
    if (existing) {
      throw new Error(`Identity already exists: ${id}`);
    }

    const now = new Date().toISOString();
    const rootKeyPair = generateEd25519KeyPair();
    const rootKey = createPrivateKeyMaterial({
      id: "root",
      publicKey: rootKeyPair.publicKey,
      privateKey: rootKeyPair.privateKey,
      purpose: "root",
      createdAt: now,
    });

    const manifest = signIdentityManifest(
      createIdentityManifestDraft(
        id,
        createPublicKeyMaterial({
          id: rootKey.id,
          publicKey: rootKey.publicKey,
          purpose: rootKey.purpose,
          createdAt: now,
        }),
        now,
      ),
      rootKey,
    );

    const record: PrivateIdentityRecord = {
      id,
      keys: {
        [rootKey.id]: rootKey,
      },
      createdAt: now,
      updatedAt: now,
    };

    await this.backend.writeManifest(manifest);
    await this.backend.writePrivateRecord(record);
    await this.recordEvent(id, "identity.created", id, rootKey.id, {
      rootKeyId: rootKey.id,
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
    const keyPair = generateEd25519KeyPair();
    const now = new Date().toISOString();
    const agentKey = createPrivateKeyMaterial({
      id: agentKeyId,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
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

    const record = await this.requirePrivateRecord(identityId);
    record.keys[agentKeyId] = agentKey;
    record.updatedAt = now;

    await this.backend.writeManifest(signed);
    await this.backend.writePrivateRecord(record);

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
    },
  ): Promise<CapabilityToken> {
    const manifest = await this.requireManifest(identityId);
    const rootKey = await this.resolveSigningKey(
      identityId,
      manifest.signatureKeyId,
    );

    const token = issueCapabilityToken({
      manifest,
      rootPrivateKey: rootKey.privateKey,
      subject: input.subject,
      permissions: input.permissions,
      denied: input.denied,
      audience: input.audience,
      ttlSeconds: input.ttlSeconds,
      nonce: input.nonce,
    });

    await this.recordEvent(identityId, "token.issued", token.id, rootKey.id, {
      subject: token.subject,
      permissions: token.permissions,
      denied: token.denied,
      audience: token.audience,
    });

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

    const record = await this.requirePrivateRecord(identityId);
    const agentMaterial = record.keys[`${input.actor}#agent`];

    if (!agentMaterial) {
      throw new Error(`Missing agent private key for ${input.actor}`);
    }

    return createSignedRequest({
      actor: input.actor,
      issuer: input.issuer,
      signatureKeyId: agent.publicKeyId,
      capabilityToken: input.capabilityToken,
      method: input.method,
      path: input.path,
      body: input.body,
      privateKey: agentMaterial.privateKey,
      nonce: input.nonce ?? randomNonce(),
      timestamp: input.timestamp,
    });
  }

  async verifyManifest(identityId: string): Promise<VerificationOutcome> {
    const manifest = await this.requireManifest(identityId);
    return verifyIdentityManifest(manifest);
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

    const signer = await this.resolveSigningKey(
      identityId,
      manifest.signatureKeyId,
      keyId,
    );
    const resigned = signIdentityManifest(
      {
        id: nextManifest.id,
        version: nextManifest.version,
        publicKeys: nextManifest.publicKeys,
        services: nextManifest.services,
        agents: nextManifest.agents,
        claims: nextManifest.claims,
        recovery: nextManifest.recovery,
        updatedAt: now,
        expiresAt: nextManifest.expiresAt,
        signatureKeyId: signer.id,
      },
      signer,
    );

    await this.backend.writeManifest(resigned);
    const event = await this.recordEvent(
      identityId,
      "key.revoked",
      keyId,
      signer.id,
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
    const record = await this.requirePrivateRecord(identityId);
    const oldRoot = await this.resolveSigningKey(
      identityId,
      manifest.signatureKeyId,
    );

    const now = new Date().toISOString();
    const keyPair = generateEd25519KeyPair();
    const newRootKey = createPrivateKeyMaterial({
      id: `root-${Date.now()}`,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      purpose: "root",
      createdAt: now,
    });

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

    const resigned = signIdentityManifest(
      {
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
      },
      newRootKey,
    );

    record.keys[newRootKey.id] = newRootKey;
    record.keys[oldRoot.id] = {
      ...oldRoot,
      status: "deprecated",
      deactivatedAt: now,
    };
    record.updatedAt = now;

    await this.backend.writeManifest(resigned);
    await this.backend.writePrivateRecord(record);
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

  private async requirePrivateRecord(
    identityId: string,
  ): Promise<PrivateIdentityRecord> {
    const record = await this.backend.readPrivateRecord(identityId);
    if (!record) {
      throw new Error(`Missing private record for: ${identityId}`);
    }

    return record;
  }

  private async currentRootKeyId(identityId: string): Promise<string> {
    const manifest = await this.requireManifest(identityId);
    return manifest.signatureKeyId;
  }

  private async resolveSigningKey(
    identityId: string,
    preferredKeyId?: string,
    fallbackKeyId?: string,
  ): Promise<PrivateKeyMaterial> {
    const record = await this.requirePrivateRecord(identityId);
    const candidateIds = [
      preferredKeyId,
      fallbackKeyId,
      (await this.requireManifest(identityId)).signatureKeyId,
    ].filter(
      (value): value is string => typeof value === "string" && value.length > 0,
    );

    for (const keyId of candidateIds) {
      const candidate = record.keys[keyId];
      if (candidate) {
        return candidate;
      }
    }

    const root = Object.values(record.keys).find(
      (entry) => entry.purpose === "root" && entry.status === "active",
    );
    if (root) {
      return root;
    }

    const anyRoot = Object.values(record.keys).find(
      (entry) => entry.purpose === "root",
    );
    if (anyRoot) {
      return anyRoot;
    }

    throw new Error(`Missing root key for: ${identityId}`);
  }

  private async recordEvent(
    identityId: string,
    type: Parameters<typeof createRegistryEventDraft>[0]["type"],
    subjectId: string,
    signerKeyId: string,
    details?: Record<string, unknown> | undefined,
  ): Promise<RegistryEvent> {
    const signer = await this.resolveSigningKey(identityId, signerKeyId);
    const events = await this.backend.listEvents(identityId);
    const previousHash = events.at(-1)?.hash ?? "genesis";
    const draft = createRegistryEventDraft({
      type,
      subjectId,
      signerKeyId: signer.id,
      previousHash,
      details,
    });

    return this.backend.appendEvent(
      identityId,
      signRegistryEvent(draft, signer.privateKey),
    );
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
    const record = await this.requirePrivateRecord(identityId);
    const rootKey = await this.resolveSigningKey(
      identityId,
      manifest.signatureKeyId,
    );
    const candidate = record.keys[rootKey.id] ?? rootKey;

    return signIdentityManifest(
      {
        id: manifest.id,
        version: manifest.version,
        publicKeys: manifest.publicKeys,
        services: manifest.services,
        agents: manifest.agents,
        claims: manifest.claims,
        recovery: manifest.recovery,
        updatedAt: new Date().toISOString(),
        expiresAt: manifest.expiresAt,
        signatureKeyId: candidate.id,
      },
      candidate,
    );
  }
}
