import type {
  IdentityManifest,
  PrivateIdentityRecord,
  ReplayStore,
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
}

export class MemoryRegistryBackend implements RegistryBackend {
  private readonly manifests = new Map<string, IdentityManifest>();
  private readonly privateRecords = new Map<string, PrivateIdentityRecord>();
  private readonly revocations = new Map<string, RevocationRecord>();
  private readonly events = new Map<string, RegistryEvent[]>();
  private readonly witnessReceipts = new Map<string, WitnessReceipt[]>();
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
