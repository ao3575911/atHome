import type { DatabaseSync as NodeSqliteDatabaseSync } from "node:sqlite";
import type {
  CustodyKeyRecord,
  IdentityManifest,
  PrivateIdentityRecord,
  RegistryCheckpoint,
  RegistryFreshnessMetadata,
  RevocationRecord,
  WitnessReceipt,
} from "../types.js";
import {
  identityManifestSchema,
  privateIdentityRecordSchema,
  revocationRecordSchema,
} from "../schemas.js";
import type { CreateCheckpointInput, RegistryBackend } from "../backend.js";
import {
  buildFreshnessMetadata,
  buildRegistryCheckpoint,
  custodyKey,
} from "../backend.js";
import type { RegistryEvent } from "../events.js";
import {
  applyRegistryEventToRevocationRecord,
  materializeRegistryEvent,
  toRegistryEventDraft,
} from "../events.js";
import { createEmptyRevocationRecord } from "../revocations.js";
import { verifySignedPayloadWithManifest } from "../signatures.js";

type SqliteModule = typeof import("node:sqlite");

const loadSqliteModule = (() => {
  let promise: Promise<SqliteModule> | null = null;
  return async (): Promise<SqliteModule> => {
    promise ??= new Function(
      "return import('node:sqlite')",
    )() as Promise<SqliteModule>;
    return promise;
  };
})();

type SqliteDatabase = NodeSqliteDatabaseSync;

type Row = Record<string, unknown>;
type ManifestWithCapabilityTokens = IdentityManifest & {
  capabilityTokens?: Array<{ id: string } & Record<string, unknown>>;
};

function stringify(value: unknown): string {
  return JSON.stringify(value);
}

function parseJson<T>(value: string | null | undefined): T | null {
  if (value === null || value === undefined) {
    return null;
  }

  return JSON.parse(value) as T;
}

function schemaTables(): string {
  return `
    CREATE TABLE IF NOT EXISTS namespaces (
      identity_id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS identity_manifests (
      identity_id TEXT PRIMARY KEY,
      manifest_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS private_identity_records (
      identity_id TEXT PRIMARY KEY,
      record_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS public_keys (
      identity_id TEXT NOT NULL,
      key_id TEXT NOT NULL,
      key_json TEXT NOT NULL,
      PRIMARY KEY (identity_id, key_id)
    );

    CREATE TABLE IF NOT EXISTS services (
      identity_id TEXT NOT NULL,
      service_id TEXT NOT NULL,
      service_json TEXT NOT NULL,
      PRIMARY KEY (identity_id, service_id)
    );

    CREATE TABLE IF NOT EXISTS agents (
      identity_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      agent_json TEXT NOT NULL,
      PRIMARY KEY (identity_id, agent_id)
    );

    CREATE TABLE IF NOT EXISTS capability_tokens (
      identity_id TEXT NOT NULL,
      token_id TEXT NOT NULL,
      token_json TEXT NOT NULL,
      PRIMARY KEY (identity_id, token_id)
    );

    CREATE TABLE IF NOT EXISTS revocations (
      identity_id TEXT PRIMARY KEY,
      revocation_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS registry_events (
      identity_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      event_index INTEGER NOT NULL,
      event_json TEXT NOT NULL,
      event_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (identity_id, event_id),
      UNIQUE (identity_id, event_index)
    );

    CREATE TABLE IF NOT EXISTS witness_receipts (
      identity_id TEXT NOT NULL,
      receipt_id TEXT NOT NULL,
      receipt_index INTEGER NOT NULL,
      receipt_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (identity_id, receipt_id),
      UNIQUE (identity_id, receipt_index)
    );

    CREATE TABLE IF NOT EXISTS replay_nonces (
      scope TEXT NOT NULL,
      nonce TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      PRIMARY KEY (scope, nonce)
    );

    CREATE TABLE IF NOT EXISTS abuse_reviews (
      review_id TEXT PRIMARY KEY,
      identity_id TEXT,
      subject_id TEXT,
      state TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `;
}

function jsonRecord<T>(row: Row | undefined, key: string): T | null {
  if (!row) {
    return null;
  }

  const value = row[key];
  if (typeof value !== "string") {
    return null;
  }

  return JSON.parse(value) as T;
}

async function openDatabase(path: string): Promise<SqliteDatabase> {
  const { DatabaseSync } = await loadSqliteModule();
  const database = new DatabaseSync(path);
  database.exec("PRAGMA foreign_keys = ON;");
  database.exec(schemaTables());
  return database;
}

export class SqliteRegistryBackend implements RegistryBackend {
  private readonly checkpoints = new Map<string, RegistryCheckpoint>();
  private readonly custodyRecords = new Map<string, CustodyKeyRecord>();

  private databasePromise: Promise<SqliteDatabase> | null = null;

  constructor(private readonly databasePath: string) {}

  private database(): Promise<SqliteDatabase> {
    this.databasePromise ??= openDatabase(this.databasePath);
    return this.databasePromise;
  }

  private async run<T>(
    callback: (db: SqliteDatabase) => T | Promise<T>,
  ): Promise<T> {
    const db = await this.database();
    return callback(db);
  }

  private async withTransaction<T>(
    callback: (db: SqliteDatabase) => T | Promise<T>,
  ): Promise<T> {
    const db = await this.database();
    db.exec("BEGIN IMMEDIATE TRANSACTION");
    try {
      const result = await callback(db);
      db.exec("COMMIT");
      return result;
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  async listIdentityIds(): Promise<string[]> {
    return this.run((db) =>
      db
        .prepare("SELECT identity_id FROM namespaces ORDER BY identity_id")
        .all()
        .map((row) => String((row as Row).identity_id)),
    );
  }

  async readManifest(id: string): Promise<IdentityManifest | null> {
    return this.run((db) => {
      const row = db
        .prepare(
          "SELECT manifest_json FROM identity_manifests WHERE identity_id = ?",
        )
        .get(id) as Row | undefined;

      const manifest = jsonRecord<IdentityManifest>(row, "manifest_json");
      return manifest ? identityManifestSchema.parse(manifest) : null;
    });
  }

  async writeManifest(manifest: IdentityManifest): Promise<void> {
    await this.run((db) => {
      const now = manifest.updatedAt;
      db.prepare(
        `
          INSERT INTO namespaces (identity_id, created_at, updated_at)
          VALUES (?, ?, ?)
          ON CONFLICT(identity_id) DO UPDATE SET updated_at = excluded.updated_at
        `,
      ).run(manifest.id, now, now);

      db.prepare(
        `
          INSERT INTO identity_manifests (identity_id, manifest_json, updated_at)
          VALUES (?, ?, ?)
          ON CONFLICT(identity_id) DO UPDATE SET
            manifest_json = excluded.manifest_json,
            updated_at = excluded.updated_at
        `,
      ).run(manifest.id, stringify(manifest), now);

      db.prepare("DELETE FROM public_keys WHERE identity_id = ?").run(
        manifest.id,
      );
      db.prepare("DELETE FROM services WHERE identity_id = ?").run(manifest.id);
      db.prepare("DELETE FROM agents WHERE identity_id = ?").run(manifest.id);
      db.prepare("DELETE FROM capability_tokens WHERE identity_id = ?").run(
        manifest.id,
      );

      for (const key of manifest.publicKeys) {
        db.prepare(
          `
            INSERT INTO public_keys (identity_id, key_id, key_json)
            VALUES (?, ?, ?)
            ON CONFLICT(identity_id, key_id) DO UPDATE SET key_json = excluded.key_json
          `,
        ).run(manifest.id, key.id, stringify(key));
      }

      for (const service of manifest.services) {
        db.prepare(
          `
            INSERT INTO services (identity_id, service_id, service_json)
            VALUES (?, ?, ?)
            ON CONFLICT(identity_id, service_id) DO UPDATE SET service_json = excluded.service_json
          `,
        ).run(manifest.id, service.id, stringify(service));
      }

      for (const agent of manifest.agents) {
        db.prepare(
          `
            INSERT INTO agents (identity_id, agent_id, agent_json)
            VALUES (?, ?, ?)
            ON CONFLICT(identity_id, agent_id) DO UPDATE SET agent_json = excluded.agent_json
          `,
        ).run(manifest.id, agent.id, stringify(agent));
      }

      for (const token of (manifest as ManifestWithCapabilityTokens)
        .capabilityTokens ?? []) {
        db.prepare(
          `
            INSERT INTO capability_tokens (identity_id, token_id, token_json)
            VALUES (?, ?, ?)
            ON CONFLICT(identity_id, token_id) DO UPDATE SET token_json = excluded.token_json
          `,
        ).run(manifest.id, token.id, stringify(token));
      }
    });
  }

  async readPrivateRecord(id: string): Promise<PrivateIdentityRecord | null> {
    return this.run((db) => {
      const row = db
        .prepare(
          "SELECT record_json FROM private_identity_records WHERE identity_id = ?",
        )
        .get(id) as Row | undefined;

      const record = jsonRecord<PrivateIdentityRecord>(row, "record_json");
      return record ? privateIdentityRecordSchema.parse(record) : null;
    });
  }

  async writePrivateRecord(record: PrivateIdentityRecord): Promise<void> {
    await this.run((db) => {
      db.prepare(
        `
          INSERT INTO private_identity_records (identity_id, record_json, created_at, updated_at)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(identity_id) DO UPDATE SET
            record_json = excluded.record_json,
            updated_at = excluded.updated_at
        `,
      ).run(record.id, stringify(record), record.createdAt, record.updatedAt);
    });
  }

  async readRevocationRecord(id: string): Promise<RevocationRecord | null> {
    return this.run((db) => {
      const row = db
        .prepare(
          "SELECT revocation_json FROM revocations WHERE identity_id = ?",
        )
        .get(id) as Row | undefined;

      const record = jsonRecord<RevocationRecord>(row, "revocation_json");
      return record ? revocationRecordSchema.parse(record) : null;
    });
  }

  async writeRevocationRecord(record: RevocationRecord): Promise<void> {
    await this.run((db) => {
      db.prepare(
        `
          INSERT INTO revocations (identity_id, revocation_json, updated_at)
          VALUES (?, ?, ?)
          ON CONFLICT(identity_id) DO UPDATE SET
            revocation_json = excluded.revocation_json,
            updated_at = excluded.updated_at
        `,
      ).run(record.id, stringify(record), record.updatedAt);
    });
  }

  async appendEvent(
    identityId: string,
    event: RegistryEvent,
  ): Promise<RegistryEvent> {
    return this.withTransaction((db) => {
      const manifestRow = db
        .prepare(
          "SELECT manifest_json FROM identity_manifests WHERE identity_id = ?",
        )
        .get(identityId) as Row | undefined;
      const manifest = jsonRecord<IdentityManifest>(
        manifestRow,
        "manifest_json",
      );
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

      const currentEvents = db
        .prepare(
          `
            SELECT event_json
            FROM registry_events
            WHERE identity_id = ?
            ORDER BY event_index ASC
          `,
        )
        .all(identityId) as Row[];
      const previousHash = currentEvents.at(-1)
        ? (jsonRecord<RegistryEvent>(currentEvents.at(-1), "event_json")
            ?.hash ?? "genesis")
        : "genesis";
      const stored = materializeRegistryEvent(identityId, event, previousHash);

      db.prepare(
        `
          INSERT INTO registry_events (
            identity_id, event_id, event_index, event_json, event_hash, created_at
          ) VALUES (?, ?, ?, ?, ?, ?)
        `,
      ).run(
        identityId,
        stored.id,
        currentEvents.length,
        stringify(stored),
        stored.hash ?? "",
        stored.timestamp,
      );

      const next = applyRegistryEventToRevocationRecord(
        jsonRecord<RevocationRecord>(
          db
            .prepare(
              "SELECT revocation_json FROM revocations WHERE identity_id = ?",
            )
            .get(identityId) as Row | undefined,
          "revocation_json",
        ) ?? createEmptyRevocationRecord(identityId, stored.timestamp),
        stored,
      );
      db.prepare(
        `
          INSERT INTO revocations (identity_id, revocation_json, updated_at)
          VALUES (?, ?, ?)
          ON CONFLICT(identity_id) DO UPDATE SET
            revocation_json = excluded.revocation_json,
            updated_at = excluded.updated_at
        `,
      ).run(identityId, stringify(next), next.updatedAt);

      return stored;
    });
  }

  async listEvents(identityId: string): Promise<RegistryEvent[]> {
    return this.run((db) =>
      db
        .prepare(
          `
            SELECT event_json
            FROM registry_events
            WHERE identity_id = ?
            ORDER BY event_index ASC
          `,
        )
        .all(identityId)
        .map((row) => {
          const event = jsonRecord<RegistryEvent>(row as Row, "event_json");
          return event ?? null;
        })
        .filter((event): event is RegistryEvent => event !== null),
    );
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
    await this.run((db) => {
      const count = db
        .prepare(
          "SELECT COUNT(*) AS count FROM witness_receipts WHERE identity_id = ?",
        )
        .get(identityId) as Row | undefined;
      const receiptIndex = Number(count?.count ?? 0);
      db.prepare(
        `
          INSERT INTO witness_receipts (
            identity_id, receipt_id, receipt_index, receipt_json, created_at
          ) VALUES (?, ?, ?, ?, ?)
        `,
      ).run(
        identityId,
        receipt.receiptId,
        receiptIndex,
        stringify(receipt),
        receipt.revokedAt,
      );
    });
  }

  async listWitnessReceipts(identityId: string): Promise<WitnessReceipt[]> {
    return this.run((db) =>
      db
        .prepare(
          `
            SELECT receipt_json
            FROM witness_receipts
            WHERE identity_id = ?
            ORDER BY receipt_index ASC
          `,
        )
        .all(identityId)
        .map((row) => jsonRecord<WitnessReceipt>(row as Row, "receipt_json"))
        .filter((receipt): receipt is WitnessReceipt => receipt !== null),
    );
  }

  async hasNonce(scope: string, nonce: string): Promise<boolean> {
    return this.run((db) => {
      const row = db
        .prepare(
          `
            SELECT expires_at
            FROM replay_nonces
            WHERE scope = ? AND nonce = ?
          `,
        )
        .get(scope, nonce) as Row | undefined;

      if (!row || typeof row.expires_at !== "string") {
        return false;
      }

      return Date.parse(row.expires_at) > Date.now();
    });
  }

  async recordNonce(
    scope: string,
    nonce: string,
    expiresAt: string,
  ): Promise<void> {
    await this.run((db) => {
      db.prepare(
        `
          INSERT INTO replay_nonces (scope, nonce, expires_at)
          VALUES (?, ?, ?)
          ON CONFLICT(scope, nonce) DO UPDATE SET expires_at = excluded.expires_at
        `,
      ).run(scope, nonce, expiresAt);
    });
  }

  async readCheckpoint(identityId: string): Promise<RegistryCheckpoint | null> {
    return this.checkpoints.get(identityId) ?? null;
  }

  async writeCheckpoint(checkpoint: RegistryCheckpoint): Promise<void> {
    this.checkpoints.set(checkpoint.identityId, checkpoint);
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
    return this.custodyRecords.get(custodyKey(identityId, keyId)) ?? null;
  }

  async writeCustodyKeyRecord(record: CustodyKeyRecord): Promise<void> {
    this.custodyRecords.set(
      custodyKey(record.identityId, record.keyId),
      record,
    );
  }

  async listCustodyKeyRecords(identityId: string): Promise<CustodyKeyRecord[]> {
    return [...this.custodyRecords.values()].filter(
      (r) => r.identityId === identityId,
    );
  }
}

export function createSqliteRegistryBackend(
  databasePath = ":memory:",
): SqliteRegistryBackend {
  return new SqliteRegistryBackend(databasePath);
}
