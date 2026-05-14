/**
 * PostgresRegistryBackend — full implementation wired to node-postgres (pg).
 *
 * `pg` is an optional runtime dependency. The backend lazily imports it so
 * the package can be type-checked without `pg` installed. Install it before
 * running migrations or calling any method:
 *
 *   npm install pg
 *   npm install --save-dev @types/pg   # for TypeScript type-checking
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
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

// ---------------------------------------------------------------------------
// Minimal pg type surface (avoids requiring @types/pg at typecheck time)
// ---------------------------------------------------------------------------

interface PgQueryResult<
  R extends Record<string, unknown> = Record<string, unknown>,
> {
  rows: R[];
  rowCount: number | null;
}

interface PgClientLike {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<PgQueryResult<R>>;
  release(): void;
}

interface PgPoolLike {
  connect(): Promise<PgClientLike>;
  end(): Promise<void>;
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<PgQueryResult<R>>;
}

type PgModule = {
  Pool: new (options: { connectionString: string; max?: number }) => PgPoolLike;
};

// ---------------------------------------------------------------------------
// Lazy pg loader
// ---------------------------------------------------------------------------

const loadPg = (() => {
  let promise: Promise<PgModule> | null = null;
  return (): Promise<PgModule> => {
    promise ??= (
      new Function("return import('pg')")() as Promise<
        { default?: PgModule } & PgModule
      >
    ).then((mod) => (mod.default ?? mod) as PgModule);
    return promise;
  };
})();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Row = Record<string, unknown>;

function stringify(value: unknown): string {
  return JSON.stringify(value);
}

function parseRow<T>(row: Row | undefined, key: string): T | null {
  if (!row) return null;
  const value = row[key];
  if (typeof value !== "string") return null;
  return JSON.parse(value) as T;
}

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// PostgresRegistryBackend
// ---------------------------------------------------------------------------

export interface PostgresRegistryBackendOptions {
  connectionString?: string | undefined;
  schema?: string | undefined;
  tablePrefix?: string | undefined;
  maxPoolSize?: number | undefined;
}

export class PostgresRegistryBackend implements RegistryBackend {
  readonly capabilities = {
    durable: true,
    transactions: true,
    appendOnlyEvents: true,
    witnessReceipts: true,
    checkpoints: true,
    custodyRecords: true,
    adapter: "postgres" as const,
  };

  private poolPromise: Promise<PgPoolLike> | null = null;
  private readonly options: PostgresRegistryBackendOptions;

  constructor(options: PostgresRegistryBackendOptions = {}) {
    this.options = options;
  }

  private pool(): Promise<PgPoolLike> {
    this.poolPromise ??= this.initPool();
    return this.poolPromise;
  }

  private async initPool(): Promise<PgPoolLike> {
    let PgModule: PgModule;
    try {
      PgModule = await loadPg();
    } catch {
      throw new Error(
        "PostgresRegistryBackend requires the 'pg' package. Run: npm install pg",
      );
    }
    const connectionString =
      this.options.connectionString ?? process.env["DATABASE_URL"];
    if (!connectionString) {
      throw new Error(
        "PostgresRegistryBackend requires a connection string. " +
          "Pass connectionString in options or set the DATABASE_URL environment variable.",
      );
    }
    return new PgModule.Pool({
      connectionString,
      max: this.options.maxPoolSize ?? 10,
    });
  }

  async runMigrations(): Promise<void> {
    const pool = await this.pool();
    const migrationsDir = join(
      dirname(fileURLToPath(import.meta.url)),
      "migrations",
    );
    const sql = await readFile(join(migrationsDir, "001_initial.sql"), "utf8");
    await pool.query(sql);
  }

  private async withTransaction<T>(
    callback: (client: PgClientLike) => Promise<T>,
  ): Promise<T> {
    const pool = await this.pool();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await callback(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  private async query<R extends Row = Row>(
    text: string,
    values?: unknown[],
  ): Promise<PgQueryResult<R>> {
    const pool = await this.pool();
    return pool.query<R>(text, values);
  }

  async end(): Promise<void> {
    if (this.poolPromise) {
      const pool = await this.poolPromise;
      await pool.end();
      this.poolPromise = null;
    }
  }

  // -------------------------------------------------------------------------
  // RegistryBackend
  // -------------------------------------------------------------------------

  async listIdentityIds(): Promise<string[]> {
    const { rows } = await this.query<{ identity_id: string }>(
      "SELECT identity_id FROM namespaces ORDER BY identity_id",
    );
    return rows.map((r) => r.identity_id);
  }

  async readManifest(id: string): Promise<IdentityManifest | null> {
    const { rows } = await this.query<{ manifest_json: string }>(
      "SELECT manifest_json FROM identity_manifests WHERE identity_id = $1",
      [id],
    );
    const raw = parseRow<unknown>(rows[0], "manifest_json");
    return raw ? identityManifestSchema.parse(raw) : null;
  }

  async writeManifest(manifest: IdentityManifest): Promise<void> {
    await this.withTransaction(async (client) => {
      await client.query(
        `INSERT INTO namespaces (identity_id, created_at, updated_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (identity_id) DO UPDATE SET updated_at = EXCLUDED.updated_at`,
        [manifest.id, manifest.updatedAt, manifest.updatedAt],
      );
      await client.query(
        `INSERT INTO identity_manifests (identity_id, manifest_json, updated_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (identity_id) DO UPDATE SET
           manifest_json = EXCLUDED.manifest_json,
           updated_at = EXCLUDED.updated_at`,
        [manifest.id, stringify(manifest), manifest.updatedAt],
      );
    });
  }

  async readPrivateRecord(id: string): Promise<PrivateIdentityRecord | null> {
    const { rows } = await this.query<{ record_json: string }>(
      "SELECT record_json FROM private_identity_records WHERE identity_id = $1",
      [id],
    );
    const raw = parseRow<unknown>(rows[0], "record_json");
    return raw ? privateIdentityRecordSchema.parse(raw) : null;
  }

  async writePrivateRecord(record: PrivateIdentityRecord): Promise<void> {
    await this.query(
      `INSERT INTO private_identity_records (identity_id, record_json, created_at, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (identity_id) DO UPDATE SET
         record_json = EXCLUDED.record_json,
         updated_at = EXCLUDED.updated_at`,
      [record.id, stringify(record), record.createdAt, record.updatedAt],
    );
  }

  async readRevocationRecord(id: string): Promise<RevocationRecord | null> {
    const { rows } = await this.query<{ revocation_json: string }>(
      "SELECT revocation_json FROM revocations WHERE identity_id = $1",
      [id],
    );
    const raw = parseRow<unknown>(rows[0], "revocation_json");
    return raw ? revocationRecordSchema.parse(raw) : null;
  }

  async writeRevocationRecord(record: RevocationRecord): Promise<void> {
    await this.query(
      `INSERT INTO revocations (identity_id, revocation_json, updated_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (identity_id) DO UPDATE SET
         revocation_json = EXCLUDED.revocation_json,
         updated_at = EXCLUDED.updated_at`,
      [record.id, stringify(record), record.updatedAt],
    );
  }

  async appendEvent(
    identityId: string,
    event: RegistryEvent,
  ): Promise<RegistryEvent> {
    return this.withTransaction(async (client) => {
      const manifestResult = await client.query<{ manifest_json: string }>(
        "SELECT manifest_json FROM identity_manifests WHERE identity_id = $1",
        [identityId],
      );
      const manifest = parseRow<IdentityManifest>(
        manifestResult.rows[0],
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

      const { rows: eventRows } = await client.query<{ event_json: string }>(
        `SELECT event_json FROM registry_events
         WHERE identity_id = $1 ORDER BY event_index ASC`,
        [identityId],
      );
      const currentEvents = eventRows
        .map((r) => parseRow<RegistryEvent>(r, "event_json"))
        .filter((e): e is RegistryEvent => e !== null);

      const previousHash = currentEvents.at(-1)?.hash ?? "genesis";

      // Validate hash chain
      if (event.previousHash && event.previousHash !== previousHash) {
        throw new Error(
          `Registry event previous hash mismatch: expected ${previousHash}, got ${event.previousHash}`,
        );
      }

      const stored = materializeRegistryEvent(identityId, event, previousHash);

      await client.query(
        `INSERT INTO registry_events
           (identity_id, event_id, event_index, event_json, event_hash, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          identityId,
          stored.id,
          currentEvents.length,
          stringify(stored),
          stored.hash ?? "",
          stored.timestamp,
        ],
      );

      const revResult = await client.query<{ revocation_json: string }>(
        "SELECT revocation_json FROM revocations WHERE identity_id = $1",
        [identityId],
      );
      const existing = parseRow<RevocationRecord>(
        revResult.rows[0],
        "revocation_json",
      );
      const next = applyRegistryEventToRevocationRecord(
        existing ?? createEmptyRevocationRecord(identityId, stored.timestamp),
        stored,
      );
      await client.query(
        `INSERT INTO revocations (identity_id, revocation_json, updated_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (identity_id) DO UPDATE SET
           revocation_json = EXCLUDED.revocation_json,
           updated_at = EXCLUDED.updated_at`,
        [identityId, stringify(next), next.updatedAt],
      );

      return stored;
    });
  }

  async listEvents(identityId: string): Promise<RegistryEvent[]> {
    const { rows } = await this.query<{ event_json: string }>(
      `SELECT event_json FROM registry_events
       WHERE identity_id = $1 ORDER BY event_index ASC`,
      [identityId],
    );
    return rows
      .map((r) => parseRow<RegistryEvent>(r, "event_json"))
      .filter((e): e is RegistryEvent => e !== null);
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
    await this.withTransaction(async (client) => {
      const { rows } = await client.query<{ count: string }>(
        "SELECT COUNT(*) AS count FROM witness_receipts WHERE identity_id = $1",
        [identityId],
      );
      const receiptIndex = parseInt(rows[0]?.count ?? "0", 10);
      await client.query(
        `INSERT INTO witness_receipts
           (identity_id, receipt_id, receipt_index, receipt_json, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (identity_id, receipt_id) DO NOTHING`,
        [
          identityId,
          receipt.receiptId,
          receiptIndex,
          stringify(receipt),
          receipt.revokedAt,
        ],
      );
    });
  }

  async listWitnessReceipts(identityId: string): Promise<WitnessReceipt[]> {
    const { rows } = await this.query<{ receipt_json: string }>(
      `SELECT receipt_json FROM witness_receipts
       WHERE identity_id = $1 ORDER BY receipt_index ASC`,
      [identityId],
    );
    return rows
      .map((r) => parseRow<WitnessReceipt>(r, "receipt_json"))
      .filter((r): r is WitnessReceipt => r !== null);
  }

  async readCheckpoint(identityId: string): Promise<RegistryCheckpoint | null> {
    const { rows } = await this.query<{ checkpoint_json: string }>(
      "SELECT checkpoint_json FROM checkpoints WHERE identity_id = $1",
      [identityId],
    );
    return parseRow<RegistryCheckpoint>(rows[0], "checkpoint_json");
  }

  async writeCheckpoint(checkpoint: RegistryCheckpoint): Promise<void> {
    const now = new Date().toISOString();
    await this.query(
      `INSERT INTO checkpoints (identity_id, checkpoint_json, updated_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (identity_id) DO UPDATE SET
         checkpoint_json = EXCLUDED.checkpoint_json,
         updated_at = EXCLUDED.updated_at`,
      [checkpoint.identityId, stringify(checkpoint), now],
    );
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
    const { rows } = await this.query<{ record_json: string }>(
      "SELECT record_json FROM custody_key_records WHERE identity_id = $1 AND key_id = $2",
      [identityId, keyId],
    );
    return parseRow<CustodyKeyRecord>(rows[0], "record_json");
  }

  async writeCustodyKeyRecord(record: CustodyKeyRecord): Promise<void> {
    const now = new Date().toISOString();
    await this.query(
      `INSERT INTO custody_key_records (identity_id, key_id, record_json, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (identity_id, key_id) DO UPDATE SET
         record_json = EXCLUDED.record_json,
         updated_at = EXCLUDED.updated_at`,
      [record.identityId, record.keyId, stringify(record), now],
    );
  }

  async listCustodyKeyRecords(identityId: string): Promise<CustodyKeyRecord[]> {
    const { rows } = await this.query<{ record_json: string }>(
      "SELECT record_json FROM custody_key_records WHERE identity_id = $1",
      [identityId],
    );
    return rows
      .map((r) => parseRow<CustodyKeyRecord>(r, "record_json"))
      .filter((r): r is CustodyKeyRecord => r !== null);
  }

  async hasNonce(scope: string, nonce: string): Promise<boolean> {
    const { rows } = await this.query<{ expires_at: string }>(
      "SELECT expires_at FROM replay_nonces WHERE scope = $1 AND nonce = $2",
      [scope, nonce],
    );
    if (!rows[0]) return false;
    return Date.parse(rows[0].expires_at) > Date.now();
  }

  async recordNonce(
    scope: string,
    nonce: string,
    expiresAt: string,
  ): Promise<void> {
    await this.query(
      `INSERT INTO replay_nonces (scope, nonce, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (scope, nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
      [scope, nonce, expiresAt],
    );
  }
}

export function createPostgresRegistryBackend(
  options: PostgresRegistryBackendOptions = {},
): PostgresRegistryBackend {
  return new PostgresRegistryBackend(options);
}
