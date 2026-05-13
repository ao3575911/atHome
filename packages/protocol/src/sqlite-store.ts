import type { DatabaseSync } from "node:sqlite";
import { createRequire } from "node:module";
import type {
  AgentDefinition,
  IdentityManifest,
  PrivateIdentityRecord,
  PublicKey,
  RevocationRecord,
  ServiceEndpoint,
  WitnessReceipt,
} from "./types.js";
import type { RegistryBackend } from "./backend.js";
import type { RegistryEvent } from "./events.js";
import {
  applyRegistryEventToRevocationRecord,
  materializeRegistryEvent,
  toRegistryEventDraft,
} from "./events.js";
import { createEmptyRevocationRecord } from "./revocations.js";
import {
  identityManifestSchema,
  privateIdentityRecordSchema,
  revocationRecordSchema,
} from "./schemas.js";
import { verifySignedPayloadWithManifest } from "./signatures.js";

type ReplayState = {
  nonces: Record<string, string>;
};

type JsonRow = {
  json: string;
};

type HashRow = {
  hash: string | null;
};

export interface SQLiteRegistryBackendOptions {
  namespaceId?: string | undefined;
  timeoutMs?: number | undefined;
}

export class SQLiteRegistryBackend implements RegistryBackend {
  private readonly db: DatabaseSync;
  private readonly namespaceId: string;
  private initialized = false;

  constructor(path = ":memory:", options: SQLiteRegistryBackendOptions = {}) {
    const { DatabaseSync: SQLiteDatabaseSync } = createRequire(import.meta.url)(
      "node:sqlite",
    ) as {
      DatabaseSync: new (
        path: string,
        options?: { timeout?: number | undefined },
      ) => DatabaseSync;
    };
    this.db = new SQLiteDatabaseSync(path, {
      timeout: options.timeoutMs ?? 5000,
    });
    this.namespaceId = options.namespaceId ?? "default";
  }

  private get database(): DatabaseSync {
    return this.db;
  }

  init(): void {
    if (this.initialized) {
      return;
    }

    this.database.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;

      CREATE TABLE IF NOT EXISTS registry_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS namespaces (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS identity_manifests (
        namespace_id TEXT NOT NULL,
        id TEXT NOT NULL,
        version TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        signature_key_id TEXT NOT NULL,
        signature TEXT NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, id),
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE TABLE IF NOT EXISTS private_identity_records (
        namespace_id TEXT NOT NULL,
        id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, id),
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE TABLE IF NOT EXISTS public_keys (
        namespace_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        id TEXT NOT NULL,
        type TEXT NOT NULL,
        purpose TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        deactivated_at TEXT,
        revoked_at TEXT,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, identity_id, id),
        FOREIGN KEY (namespace_id, identity_id)
          REFERENCES identity_manifests(namespace_id, id)
          ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS services (
        namespace_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        id TEXT NOT NULL,
        type TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        public_key_id TEXT,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, identity_id, id),
        FOREIGN KEY (namespace_id, identity_id)
          REFERENCES identity_manifests(namespace_id, id)
          ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS agents (
        namespace_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        id TEXT NOT NULL,
        owner TEXT NOT NULL,
        public_key_id TEXT NOT NULL,
        status TEXT NOT NULL,
        expires_at TEXT,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, identity_id, id),
        FOREIGN KEY (namespace_id, identity_id)
          REFERENCES identity_manifests(namespace_id, id)
          ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS capability_tokens (
        namespace_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        id TEXT NOT NULL,
        subject TEXT NOT NULL,
        audience TEXT,
        issued_at TEXT,
        expires_at TEXT,
        revoked_at TEXT,
        json TEXT,
        PRIMARY KEY (namespace_id, identity_id, id),
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE TABLE IF NOT EXISTS revocations (
        namespace_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, identity_id),
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE TABLE IF NOT EXISTS registry_events (
        namespace_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        id TEXT NOT NULL,
        type TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        signer_key_id TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, identity_id, sequence),
        UNIQUE (namespace_id, identity_id, id),
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE TABLE IF NOT EXISTS witness_receipts (
        namespace_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        receipt_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        revoked_at TEXT NOT NULL,
        log_index INTEGER NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (namespace_id, identity_id, receipt_id),
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE TABLE IF NOT EXISTS replay_nonces (
        namespace_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        PRIMARY KEY (namespace_id, scope, nonce),
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE TABLE IF NOT EXISTS abuse_reviews (
        namespace_id TEXT NOT NULL,
        id TEXT PRIMARY KEY,
        identity_id TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        json TEXT NOT NULL,
        FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
      );

      CREATE INDEX IF NOT EXISTS registry_events_identity_idx
        ON registry_events(namespace_id, identity_id, sequence);
      CREATE INDEX IF NOT EXISTS replay_nonces_expiry_idx
        ON replay_nonces(namespace_id, expires_at);
    `);

    this.database
      .prepare(
        `INSERT OR IGNORE INTO namespaces (id, created_at) VALUES (?, ?)`,
      )
      .run(this.namespaceId, new Date().toISOString());
    this.database
      .prepare(
        `INSERT OR IGNORE INTO registry_migrations (version, applied_at)
         VALUES (1, ?)`,
      )
      .run(new Date().toISOString());
    this.initialized = true;
  }

  close(): void {
    this.database.close();
  }

  async listIdentityIds(): Promise<string[]> {
    this.init();
    return this.database
      .prepare(
        `SELECT id FROM identity_manifests WHERE namespace_id = ? ORDER BY id`,
      )
      .all(this.namespaceId)
      .map((row) => String(row.id));
  }

  async readManifest(id: string): Promise<IdentityManifest | null> {
    this.init();
    const row = this.database
      .prepare(
        `SELECT json FROM identity_manifests
         WHERE namespace_id = ? AND id = ?`,
      )
      .get(this.namespaceId, id) as JsonRow | undefined;

    return row ? identityManifestSchema.parse(JSON.parse(row.json)) : null;
  }

  async writeManifest(manifest: IdentityManifest): Promise<void> {
    this.init();
    this.transaction(() => {
      this.database
        .prepare(
          `INSERT INTO identity_manifests
             (namespace_id, id, version, updated_at, signature_key_id, signature, json)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(namespace_id, id) DO UPDATE SET
             version = excluded.version,
             updated_at = excluded.updated_at,
             signature_key_id = excluded.signature_key_id,
             signature = excluded.signature,
             json = excluded.json`,
        )
        .run(
          this.namespaceId,
          manifest.id,
          manifest.version,
          manifest.updatedAt,
          manifest.signatureKeyId,
          manifest.signature,
          toJson(manifest),
        );

      this.replaceManifestChildren(manifest);
    });
  }

  async readPrivateRecord(id: string): Promise<PrivateIdentityRecord | null> {
    this.init();
    const row = this.database
      .prepare(
        `SELECT json FROM private_identity_records
         WHERE namespace_id = ? AND id = ?`,
      )
      .get(this.namespaceId, id) as JsonRow | undefined;

    return row ? privateIdentityRecordSchema.parse(JSON.parse(row.json)) : null;
  }

  async writePrivateRecord(record: PrivateIdentityRecord): Promise<void> {
    this.init();
    this.database
      .prepare(
        `INSERT INTO private_identity_records
           (namespace_id, id, created_at, updated_at, json)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(namespace_id, id) DO UPDATE SET
           created_at = excluded.created_at,
           updated_at = excluded.updated_at,
           json = excluded.json`,
      )
      .run(
        this.namespaceId,
        record.id,
        record.createdAt,
        record.updatedAt,
        toJson(record),
      );
  }

  async readRevocationRecord(id: string): Promise<RevocationRecord | null> {
    this.init();
    const row = this.database
      .prepare(
        `SELECT json FROM revocations
         WHERE namespace_id = ? AND identity_id = ?`,
      )
      .get(this.namespaceId, id) as JsonRow | undefined;

    return row ? revocationRecordSchema.parse(JSON.parse(row.json)) : null;
  }

  async writeRevocationRecord(record: RevocationRecord): Promise<void> {
    this.init();
    this.writeRevocationRecordSync(record);
  }

  async appendEvent(
    identityId: string,
    event: RegistryEvent,
  ): Promise<RegistryEvent> {
    this.init();
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

    let stored: RegistryEvent | undefined;
    this.transaction(() => {
      const previousHash = this.currentEventHash(identityId);
      stored = materializeRegistryEvent(identityId, event, previousHash);
      const sequence = this.nextEventSequence(identityId);
      this.database
        .prepare(
          `INSERT INTO registry_events
             (namespace_id, identity_id, sequence, id, type, subject_id,
              timestamp, signer_key_id, previous_hash, payload_hash, hash,
              signature, json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          this.namespaceId,
          identityId,
          sequence,
          stored.id,
          stored.type,
          stored.subjectId,
          stored.timestamp,
          stored.signerKeyId,
          stored.previousHash,
          stored.payloadHash,
          stored.hash ?? "",
          stored.signature,
          toJson(stored),
        );

      const current =
        this.readRevocationRecordSync(identityId) ??
        createEmptyRevocationRecord(identityId, stored.timestamp);
      this.writeRevocationRecordSync(
        applyRegistryEventToRevocationRecord(current, stored),
      );
    });

    return clone(stored);
  }

  async listEvents(identityId: string): Promise<RegistryEvent[]> {
    this.init();
    return this.database
      .prepare(
        `SELECT json FROM registry_events
         WHERE namespace_id = ? AND identity_id = ?
         ORDER BY sequence`,
      )
      .all(this.namespaceId, identityId)
      .map((row) => JSON.parse(String(row.json)) as RegistryEvent);
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
    this.init();
    this.database
      .prepare(
        `INSERT INTO witness_receipts
           (namespace_id, identity_id, receipt_id, event_id, event_hash, kind,
            subject_id, revoked_at, log_index, json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(namespace_id, identity_id, receipt_id) DO UPDATE SET
           event_id = excluded.event_id,
           event_hash = excluded.event_hash,
           kind = excluded.kind,
           subject_id = excluded.subject_id,
           revoked_at = excluded.revoked_at,
           log_index = excluded.log_index,
           json = excluded.json`,
      )
      .run(
        this.namespaceId,
        identityId,
        receipt.receiptId,
        receipt.eventId,
        receipt.eventHash,
        receipt.kind,
        receipt.subjectId,
        receipt.revokedAt,
        receipt.logIndex,
        toJson(receipt),
      );
  }

  async listWitnessReceipts(identityId: string): Promise<WitnessReceipt[]> {
    this.init();
    return this.database
      .prepare(
        `SELECT json FROM witness_receipts
         WHERE namespace_id = ? AND identity_id = ?
         ORDER BY log_index, receipt_id`,
      )
      .all(this.namespaceId, identityId)
      .map((row) => JSON.parse(String(row.json)) as WitnessReceipt);
  }

  async readReplayState(): Promise<ReplayState> {
    this.init();
    this.pruneExpiredNonces();
    const rows = this.database
      .prepare(
        `SELECT scope, nonce, expires_at FROM replay_nonces
         WHERE namespace_id = ?
         ORDER BY scope, nonce`,
      )
      .all(this.namespaceId);
    const nonces: Record<string, string> = {};
    for (const row of rows) {
      nonces[`${String(row.scope)}:${String(row.nonce)}`] = String(
        row.expires_at,
      );
    }
    return { nonces };
  }

  async hasNonce(scope: string, nonce: string): Promise<boolean> {
    this.init();
    this.pruneExpiredNonces();
    const row = this.database
      .prepare(
        `SELECT 1 AS found FROM replay_nonces
         WHERE namespace_id = ? AND scope = ? AND nonce = ?`,
      )
      .get(this.namespaceId, scope, nonce);
    return row !== undefined;
  }

  async recordNonce(
    scope: string,
    nonce: string,
    expiresAt: string,
  ): Promise<void> {
    this.init();
    this.pruneExpiredNonces();
    this.database
      .prepare(
        `INSERT INTO replay_nonces (namespace_id, scope, nonce, expires_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(namespace_id, scope, nonce) DO UPDATE SET
           expires_at = excluded.expires_at`,
      )
      .run(this.namespaceId, scope, nonce, expiresAt);
  }

  private replaceManifestChildren(manifest: IdentityManifest): void {
    for (const table of ["public_keys", "services", "agents"]) {
      this.database
        .prepare(
          `DELETE FROM ${table} WHERE namespace_id = ? AND identity_id = ?`,
        )
        .run(this.namespaceId, manifest.id);
    }

    for (const key of manifest.publicKeys) {
      this.insertPublicKey(manifest.id, key);
    }
    for (const service of manifest.services) {
      this.insertService(manifest.id, service);
    }
    for (const agent of manifest.agents) {
      this.insertAgent(manifest.id, agent);
    }
  }

  private insertPublicKey(identityId: string, key: PublicKey): void {
    this.database
      .prepare(
        `INSERT INTO public_keys
           (namespace_id, identity_id, id, type, purpose, status, created_at,
            expires_at, deactivated_at, revoked_at, json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        this.namespaceId,
        identityId,
        key.id,
        key.type,
        key.purpose,
        key.status,
        key.createdAt,
        key.expiresAt ?? null,
        key.deactivatedAt ?? null,
        key.revokedAt ?? null,
        toJson(key),
      );
  }

  private insertService(identityId: string, service: ServiceEndpoint): void {
    this.database
      .prepare(
        `INSERT INTO services
           (namespace_id, identity_id, id, type, endpoint, public_key_id, json)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        this.namespaceId,
        identityId,
        service.id,
        service.type,
        service.endpoint,
        service.publicKeyId ?? null,
        toJson(service),
      );
  }

  private insertAgent(identityId: string, agent: AgentDefinition): void {
    this.database
      .prepare(
        `INSERT INTO agents
           (namespace_id, identity_id, id, owner, public_key_id, status,
            expires_at, json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        this.namespaceId,
        identityId,
        agent.id,
        agent.owner,
        agent.publicKeyId,
        agent.status,
        agent.expiresAt ?? null,
        toJson(agent),
      );
  }

  private currentEventHash(identityId: string): string {
    const row = this.database
      .prepare(
        `SELECT hash FROM registry_events
         WHERE namespace_id = ? AND identity_id = ?
         ORDER BY sequence DESC
         LIMIT 1`,
      )
      .get(this.namespaceId, identityId) as HashRow | undefined;
    return row?.hash ?? "genesis";
  }

  private nextEventSequence(identityId: string): number {
    const row = this.database
      .prepare(
        `SELECT COALESCE(MAX(sequence), -1) + 1 AS sequence
         FROM registry_events
         WHERE namespace_id = ? AND identity_id = ?`,
      )
      .get(this.namespaceId, identityId);
    return Number(row?.sequence ?? 0);
  }

  private readRevocationRecordSync(id: string): RevocationRecord | null {
    const row = this.database
      .prepare(
        `SELECT json FROM revocations
         WHERE namespace_id = ? AND identity_id = ?`,
      )
      .get(this.namespaceId, id) as JsonRow | undefined;
    return row ? revocationRecordSchema.parse(JSON.parse(row.json)) : null;
  }

  private writeRevocationRecordSync(record: RevocationRecord): void {
    this.database
      .prepare(
        `INSERT INTO revocations (namespace_id, identity_id, updated_at, json)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(namespace_id, identity_id) DO UPDATE SET
           updated_at = excluded.updated_at,
           json = excluded.json`,
      )
      .run(this.namespaceId, record.id, record.updatedAt, toJson(record));
  }

  private pruneExpiredNonces(): void {
    this.database
      .prepare(
        `DELETE FROM replay_nonces
         WHERE namespace_id = ? AND expires_at <= ?`,
      )
      .run(this.namespaceId, new Date().toISOString());
  }

  private transaction(action: () => void): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      action();
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
}

export function createSQLiteRegistryBackend(
  path = ":memory:",
  options: SQLiteRegistryBackendOptions = {},
): SQLiteRegistryBackend {
  return new SQLiteRegistryBackend(path, options);
}

function toJson(value: unknown): string {
  return JSON.stringify(value);
}

function clone<T>(value: T | undefined): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
