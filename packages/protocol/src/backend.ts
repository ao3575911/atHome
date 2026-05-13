import type {
  CustodyKeyRecord,
  IdentityManifest,
  PrivateIdentityRecord,
  ReplayStore,
  RegistryCheckpoint,
  RegistryFreshnessMetadata,
  RevocationRecord,
  WitnessReceipt,
} from "./types.js";
import { createEmptyRevocationRecord } from "./revocations.js";
import type { RegistryEvent } from "./events.js";
import {
  materializeRegistryEvent,
  applyRegistryEventToRevocationRecord,
  toRegistryEventDraft,
} from "./events.js";
import { canonicalize } from "./canonical.js";
import { sha256 } from "./crypto.js";
import { verifySignedPayloadWithManifest } from "./signatures.js";

export interface RegistryBackend extends ReplayStore {
  readonly capabilities?: RegistryBackendCapabilities | undefined;
  listIdentityIds(): Promise<string[]>;
  readManifest(id: string): Promise<IdentityManifest | null>;
  writeManifest(manifest: IdentityManifest): Promise<void>;
  readPrivateRecord(id: string): Promise<PrivateIdentityRecord | null>;
  writePrivateRecord(record: PrivateIdentityRecord): Promise<void>;
  readRevocationRecord(id: string): Promise<RevocationRecord | null>;
  writeRevocationRecord(record: RevocationRecord): Promise<void>;
  appendEvent(identityId: string, event: RegistryEvent): Promise<RegistryEvent>;
  listEvents(identityId: string): Promise<RegistryEvent[]>;
  getRevocationState(identityId: string): Promise<RevocationRecord | null>;
  attachWitnessReceipt(
    identityId: string,
    receipt: WitnessReceipt,
  ): Promise<void>;
  listWitnessReceipts(identityId: string): Promise<WitnessReceipt[]>;
  readCheckpoint(identityId: string): Promise<RegistryCheckpoint | null>;
  writeCheckpoint(checkpoint: RegistryCheckpoint): Promise<void>;
  createCheckpoint(
    identityId: string,
    input?: CreateCheckpointInput,
  ): Promise<RegistryCheckpoint>;
  getFreshnessMetadata(identityId: string): Promise<RegistryFreshnessMetadata>;
  readCustodyKeyRecord(
    identityId: string,
    keyId: string,
  ): Promise<CustodyKeyRecord | null>;
  writeCustodyKeyRecord(record: CustodyKeyRecord): Promise<void>;
  listCustodyKeyRecords(identityId: string): Promise<CustodyKeyRecord[]>;
}

export interface RegistryBackendCapabilities {
  durable: boolean;
  transactions: boolean;
  appendOnlyEvents: boolean;
  witnessReceipts: boolean;
  checkpoints: boolean;
  custodyRecords: boolean;
  adapter: "memory" | "local-json" | "postgres" | (string & {});
}

export interface CreateCheckpointInput {
  issuedAt?: string | undefined;
  witnessKeyId?: string | undefined;
  signature?: string | undefined;
}

export interface PostgresRegistryBackendOptions {
  connectionString?: string | undefined;
  schema?: string | undefined;
  tablePrefix?: string | undefined;
  maxPoolSize?: number | undefined;
}

export class MemoryRegistryBackend implements RegistryBackend {
  readonly capabilities: RegistryBackendCapabilities = {
    durable: false,
    transactions: false,
    appendOnlyEvents: true,
    witnessReceipts: true,
    checkpoints: true,
    custodyRecords: true,
    adapter: "memory",
  };

  private readonly manifests = new Map<string, IdentityManifest>();
  private readonly privateRecords = new Map<string, PrivateIdentityRecord>();
  private readonly revocations = new Map<string, RevocationRecord>();
  private readonly events = new Map<string, RegistryEvent[]>();
  private readonly witnessReceipts = new Map<string, WitnessReceipt[]>();
  private readonly checkpoints = new Map<string, RegistryCheckpoint>();
  private readonly custody = new Map<string, CustodyKeyRecord>();
  private readonly replay = new Map<string, string>();

  async listIdentityIds(): Promise<string[]> {
    return [...this.manifests.keys()];
  }

  async readManifest(id: string): Promise<IdentityManifest | null> {
    return this.clone(this.manifests.get(id) ?? null);
  }

  async writeManifest(manifest: IdentityManifest): Promise<void> {
    this.manifests.set(manifest.id, this.clone(manifest));
  }

  async readPrivateRecord(id: string): Promise<PrivateIdentityRecord | null> {
    return this.clone(this.privateRecords.get(id) ?? null);
  }

  async writePrivateRecord(record: PrivateIdentityRecord): Promise<void> {
    this.privateRecords.set(record.id, this.clone(record));
  }

  async readRevocationRecord(id: string): Promise<RevocationRecord | null> {
    return this.clone(this.revocations.get(id) ?? null);
  }

  async writeRevocationRecord(record: RevocationRecord): Promise<void> {
    this.revocations.set(record.id, this.clone(record));
  }

  async appendEvent(
    identityId: string,
    event: RegistryEvent,
  ): Promise<RegistryEvent> {
    const manifest = await this.readManifest(identityId);
    if (!manifest) {
      throw new Error(`Unknown identity: ${identityId}`);
    }

    const signatureCheck = verifySignedPayloadWithManifest(
      toRegistryEventDraft(event),
      event.signature,
      manifest,
      event.signerKeyId,
      {
        allowDeprecated: true,
        invalidSignatureCode: "invalid_manifest_signature",
        missingKeyCode: "key_not_found",
        revokedKeyCode: "key_revoked",
        deprecatedKeyCode: "key_deprecated",
      },
    );

    if (!signatureCheck.ok) {
      throw new Error(
        signatureCheck.reason ?? "invalid_registry_event_signature",
      );
    }

    const current = this.events.get(identityId) ?? [];
    const previousHash = current.at(-1)?.hash ?? "genesis";
    const stored = materializeRegistryEvent(identityId, event, previousHash);

    current.push(this.clone(stored));
    this.events.set(identityId, current);

    const next = applyRegistryEventToRevocationRecord(
      this.revocations.get(identityId) ??
        createEmptyRevocationRecord(identityId, event.timestamp),
      stored,
    );
    this.revocations.set(identityId, next);

    return this.clone(stored);
  }

  async listEvents(identityId: string): Promise<RegistryEvent[]> {
    return this.clone(this.events.get(identityId) ?? []);
  }

  async getRevocationState(
    identityId: string,
  ): Promise<RevocationRecord | null> {
    return this.readRevocationRecord(identityId);
  }

  async attachWitnessReceipt(
    identityId: string,
    receipt: WitnessReceipt,
  ): Promise<void> {
    const current = this.witnessReceipts.get(identityId) ?? [];
    current.push(this.clone(receipt));
    this.witnessReceipts.set(identityId, current);
  }

  async listWitnessReceipts(identityId: string): Promise<WitnessReceipt[]> {
    return this.clone(this.witnessReceipts.get(identityId) ?? []);
  }

  async readCheckpoint(identityId: string): Promise<RegistryCheckpoint | null> {
    return this.clone(this.checkpoints.get(identityId) ?? null);
  }

  async writeCheckpoint(checkpoint: RegistryCheckpoint): Promise<void> {
    this.checkpoints.set(checkpoint.identityId, this.clone(checkpoint));
  }

  async createCheckpoint(
    identityId: string,
    input: CreateCheckpointInput = {},
  ): Promise<RegistryCheckpoint> {
    const checkpoint = buildRegistryCheckpoint({
      identityId,
      events: await this.listEvents(identityId),
      receipts: await this.listWitnessReceipts(identityId),
      issuedAt: input.issuedAt,
      witnessKeyId: input.witnessKeyId,
      signature: input.signature,
    });
    await this.writeCheckpoint(checkpoint);
    return checkpoint;
  }

  async getFreshnessMetadata(
    identityId: string,
  ): Promise<RegistryFreshnessMetadata> {
    return buildFreshnessMetadata({
      identityId,
      manifest: await this.readManifest(identityId),
      revocation: await this.readRevocationRecord(identityId),
      events: await this.listEvents(identityId),
      receipts: await this.listWitnessReceipts(identityId),
      checkpoint: await this.readCheckpoint(identityId),
    });
  }

  async readCustodyKeyRecord(
    identityId: string,
    keyId: string,
  ): Promise<CustodyKeyRecord | null> {
    return this.clone(this.custody.get(custodyKey(identityId, keyId)) ?? null);
  }

  async writeCustodyKeyRecord(record: CustodyKeyRecord): Promise<void> {
    this.custody.set(
      custodyKey(record.identityId, record.keyId),
      this.clone(record),
    );
  }

  async listCustodyKeyRecords(identityId: string): Promise<CustodyKeyRecord[]> {
    return this.clone(
      [...this.custody.values()].filter(
        (record) => record.identityId === identityId,
      ),
    );
  }

  async readReplayState(): Promise<{ nonces: Record<string, string> }> {
    return { nonces: Object.fromEntries(this.replay.entries()) };
  }

  async hasNonce(scope: string, nonce: string): Promise<boolean> {
    return this.replay.has(`${scope}:${nonce}`);
  }

  async recordNonce(
    scope: string,
    nonce: string,
    expiresAt: string,
  ): Promise<void> {
    this.replay.set(`${scope}:${nonce}`, expiresAt);
  }

  private clone<T>(value: T): T {
    return value === null ? value : (JSON.parse(JSON.stringify(value)) as T);
  }
}

export function createMemoryRegistryBackend(): RegistryBackend {
  return new MemoryRegistryBackend();
}

export class PostgresRegistryBackend implements RegistryBackend {
  readonly capabilities: RegistryBackendCapabilities = {
    durable: true,
    transactions: true,
    appendOnlyEvents: true,
    witnessReceipts: true,
    checkpoints: true,
    custodyRecords: true,
    adapter: "postgres",
  };

  constructor(readonly options: PostgresRegistryBackendOptions = {}) {}

  listIdentityIds(): Promise<string[]> {
    return this.unavailable();
  }

  readManifest(_id: string): Promise<IdentityManifest | null> {
    return this.unavailable();
  }

  writeManifest(_manifest: IdentityManifest): Promise<void> {
    return this.unavailable();
  }

  readPrivateRecord(_id: string): Promise<PrivateIdentityRecord | null> {
    return this.unavailable();
  }

  writePrivateRecord(_record: PrivateIdentityRecord): Promise<void> {
    return this.unavailable();
  }

  readRevocationRecord(_id: string): Promise<RevocationRecord | null> {
    return this.unavailable();
  }

  writeRevocationRecord(_record: RevocationRecord): Promise<void> {
    return this.unavailable();
  }

  appendEvent(
    _identityId: string,
    _event: RegistryEvent,
  ): Promise<RegistryEvent> {
    return this.unavailable();
  }

  listEvents(_identityId: string): Promise<RegistryEvent[]> {
    return this.unavailable();
  }

  getRevocationState(_identityId: string): Promise<RevocationRecord | null> {
    return this.unavailable();
  }

  attachWitnessReceipt(
    _identityId: string,
    _receipt: WitnessReceipt,
  ): Promise<void> {
    return this.unavailable();
  }

  listWitnessReceipts(_identityId: string): Promise<WitnessReceipt[]> {
    return this.unavailable();
  }

  readCheckpoint(_identityId: string): Promise<RegistryCheckpoint | null> {
    return this.unavailable();
  }

  writeCheckpoint(_checkpoint: RegistryCheckpoint): Promise<void> {
    return this.unavailable();
  }

  createCheckpoint(
    _identityId: string,
    _input?: CreateCheckpointInput,
  ): Promise<RegistryCheckpoint> {
    return this.unavailable();
  }

  getFreshnessMetadata(
    _identityId: string,
  ): Promise<RegistryFreshnessMetadata> {
    return this.unavailable();
  }

  readCustodyKeyRecord(
    _identityId: string,
    _keyId: string,
  ): Promise<CustodyKeyRecord | null> {
    return this.unavailable();
  }

  writeCustodyKeyRecord(_record: CustodyKeyRecord): Promise<void> {
    return this.unavailable();
  }

  listCustodyKeyRecords(_identityId: string): Promise<CustodyKeyRecord[]> {
    return this.unavailable();
  }

  hasNonce(_scope: string, _nonce: string): Promise<boolean> {
    return this.unavailable();
  }

  recordNonce(
    _scope: string,
    _nonce: string,
    _expiresAt: string,
  ): Promise<void> {
    return this.unavailable();
  }

  private unavailable<T>(): Promise<T> {
    return Promise.reject(
      new Error(
        "PostgresRegistryBackend is an adapter contract placeholder; provide an implementation wired to a Postgres client before use.",
      ),
    );
  }
}

export function createPostgresRegistryBackend(
  options: PostgresRegistryBackendOptions = {},
): RegistryBackend {
  return new PostgresRegistryBackend(options);
}

export function registryEventHash(event: RegistryEvent): string {
  return sha256(
    canonicalize({
      identityId: event.identityId,
      id: event.id,
      type: event.type,
      subjectId: event.subjectId,
      timestamp: event.timestamp,
      signerKeyId: event.signerKeyId,
      previousHash: event.previousHash,
      payloadHash: event.payloadHash,
      details: event.details,
      signature: event.signature,
    }),
  );
}

export function buildRegistryCheckpoint(input: {
  identityId: string;
  events: RegistryEvent[];
  receipts: WitnessReceipt[];
  issuedAt?: string | undefined;
  witnessKeyId?: string | undefined;
  signature?: string | undefined;
}): RegistryCheckpoint {
  const latestEvent = input.events.at(-1);
  const latestReceipt = input.receipts.at(-1);
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  const checkpointDraft = {
    identityId: input.identityId,
    eventCount: input.events.length,
    latestEventId: latestEvent?.id,
    latestEventHash: latestEvent?.hash,
    latestEventTimestamp: latestEvent?.timestamp,
    witnessReceiptCount: input.receipts.length,
    latestWitnessReceiptId: latestReceipt?.receiptId,
    issuedAt,
    witnessKeyId: input.witnessKeyId,
  };

  return {
    ...checkpointDraft,
    checkpointId: sha256(canonicalize(checkpointDraft)),
    signature: input.signature,
  };
}

export function buildFreshnessMetadata(input: {
  identityId: string;
  manifest: IdentityManifest | null;
  revocation: RevocationRecord | null;
  events: RegistryEvent[];
  receipts: WitnessReceipt[];
  checkpoint: RegistryCheckpoint | null;
  generatedAt?: string | undefined;
}): RegistryFreshnessMetadata {
  const latestEvent = input.events.at(-1);
  return {
    identityId: input.identityId,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    manifestUpdatedAt: input.manifest?.updatedAt,
    revocationUpdatedAt: input.revocation?.updatedAt,
    latestEventId: latestEvent?.id,
    latestEventHash: latestEvent?.hash,
    latestEventTimestamp: latestEvent?.timestamp,
    eventCount: input.events.length,
    witnessReceiptCount: input.receipts.length,
    checkpoint: input.checkpoint ?? undefined,
  };
}

export function custodyKey(identityId: string, keyId: string): string {
  return `${identityId}:${keyId}`;
}
