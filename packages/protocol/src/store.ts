import {
  mkdir,
  readFile,
  readdir,
  rm,
  rename,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import type {
  IdentityManifest,
  PrivateIdentityRecord,
  ReplayStore,
  RevocationRecord,
  WitnessReceipt,
} from "./types.js";
import {
  identityManifestSchema,
  privateIdentityRecordSchema,
  revocationRecordSchema,
} from "./schemas.js";
import type { RegistryBackend } from "./backend.js";
import type { RegistryEvent } from "./events.js";
import {
  applyRegistryEventToRevocationRecord,
  materializeRegistryEvent,
  toRegistryEventDraft,
} from "./events.js";
import { createEmptyRevocationRecord } from "./revocations.js";
import { verifySignedPayloadWithManifest } from "./signatures.js";

async function ensureDirectory(filePath: string): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const content = await readFile(filePath, "utf8");
    return JSON.parse(content) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }

    throw error;
  }
}

async function writeJsonFile(filePath: string, value: unknown): Promise<void> {
  await ensureDirectory(filePath);
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await rename(tempPath, filePath);
}

function manifestPath(baseDir: string, id: string): string {
  return join(baseDir, "manifests", `${id}.json`);
}

function privatePath(baseDir: string, id: string): string {
  return join(baseDir, "private", `${id}.json`);
}

function revocationPath(baseDir: string, id: string): string {
  return join(baseDir, "revocations", `${id}.json`);
}

function eventsPath(baseDir: string, id: string): string {
  return join(baseDir, "events", `${id}.json`);
}

function replayPath(baseDir: string): string {
  return join(baseDir, "replay.json");
}

type ReplayState = {
  nonces: Record<string, string>;
};

async function loadReplayState(baseDir: string): Promise<ReplayState> {
  const current = (await readJsonFile<ReplayState>(replayPath(baseDir))) ?? {
    nonces: {},
  };
  const now = Date.now();
  let dirty = false;
  const next: ReplayState = { nonces: {} };

  for (const [key, expiresAt] of Object.entries(current.nonces)) {
    if (Date.parse(expiresAt) > now) {
      next.nonces[key] = expiresAt;
    } else {
      dirty = true;
    }
  }

  if (dirty) {
    await writeJsonFile(replayPath(baseDir), next);
  }

  return next;
}

export class LocalJsonStore implements RegistryBackend {
  constructor(private readonly baseDir: string) {}

  async init(): Promise<void> {
    await mkdir(join(this.baseDir, "manifests"), { recursive: true });
    await mkdir(join(this.baseDir, "private"), { recursive: true });
    await mkdir(join(this.baseDir, "revocations"), { recursive: true });
    await mkdir(join(this.baseDir, "events"), { recursive: true });
    await mkdir(join(this.baseDir, "witness"), { recursive: true });
  }

  async listIdentityIds(): Promise<string[]> {
    await this.init();
    const files = await readdir(join(this.baseDir, "manifests"));
    return files
      .filter((file) => file.endsWith(".json"))
      .map((file) => file.replace(/\.json$/u, ""));
  }

  async readManifest(id: string): Promise<IdentityManifest | null> {
    await this.init();
    const manifest = await readJsonFile<IdentityManifest>(
      manifestPath(this.baseDir, id),
    );
    if (!manifest) {
      return null;
    }

    return identityManifestSchema.parse(manifest);
  }

  async writeManifest(manifest: IdentityManifest): Promise<void> {
    await this.init();
    await writeJsonFile(manifestPath(this.baseDir, manifest.id), manifest);
  }

  async readPrivateRecord(id: string): Promise<PrivateIdentityRecord | null> {
    await this.init();
    const record = await readJsonFile<PrivateIdentityRecord>(
      privatePath(this.baseDir, id),
    );
    if (!record) {
      return null;
    }

    return privateIdentityRecordSchema.parse(record);
  }

  async writePrivateRecord(record: PrivateIdentityRecord): Promise<void> {
    await this.init();
    await writeJsonFile(privatePath(this.baseDir, record.id), record);
  }

  async readRevocationRecord(id: string): Promise<RevocationRecord | null> {
    await this.init();
    const record = await readJsonFile<RevocationRecord>(
      revocationPath(this.baseDir, id),
    );
    if (!record) {
      return null;
    }

    return revocationRecordSchema.parse(record);
  }

  async writeRevocationRecord(record: RevocationRecord): Promise<void> {
    await this.init();
    await writeJsonFile(revocationPath(this.baseDir, record.id), record);
  }

  async appendEvent(
    identityId: string,
    event: RegistryEvent,
  ): Promise<RegistryEvent> {
    await this.init();
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

    const current = (await this.readEvents(identityId)).slice();
    const previousHash = current.at(-1)?.hash ?? "genesis";
    const stored = materializeRegistryEvent(identityId, event, previousHash);
    current.push(stored);
    await writeJsonFile(eventsPath(this.baseDir, identityId), current);

    const next = applyRegistryEventToRevocationRecord(
      (await this.readRevocationRecord(identityId)) ??
        createEmptyRevocationRecord(identityId, stored.timestamp),
      stored,
    );
    await this.writeRevocationRecord(next);
    return stored;
  }

  async listEvents(identityId: string): Promise<RegistryEvent[]> {
    await this.init();
    return this.readEvents(identityId);
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
    await this.init();
    const current = (await this.readWitnessReceipts(identityId)).slice();
    current.push(receipt);
    await writeJsonFile(
      join(this.baseDir, "witness", `${identityId}.json`),
      current,
    );
  }

  async listWitnessReceipts(identityId: string): Promise<WitnessReceipt[]> {
    await this.init();
    return this.readWitnessReceipts(identityId);
  }

  async removeIdentity(id: string): Promise<void> {
    await rm(manifestPath(this.baseDir, id), { force: true });
    await rm(privatePath(this.baseDir, id), { force: true });
    await rm(revocationPath(this.baseDir, id), { force: true });
  }

  async readReplayState(): Promise<ReplayState> {
    await this.init();
    return loadReplayState(this.baseDir);
  }

  async hasNonce(scope: string, nonce: string): Promise<boolean> {
    const replay = await this.readReplayState();
    return replay.nonces[`${scope}:${nonce}`] !== undefined;
  }

  async recordNonce(
    scope: string,
    nonce: string,
    expiresAt: string,
  ): Promise<void> {
    const replay = await this.readReplayState();
    replay.nonces[`${scope}:${nonce}`] = expiresAt;
    await writeJsonFile(replayPath(this.baseDir), replay);
  }

  private async readEvents(identityId: string): Promise<RegistryEvent[]> {
    const current = await readJsonFile<RegistryEvent[]>(
      eventsPath(this.baseDir, identityId),
    );
    return current ?? [];
  }

  private async readWitnessReceipts(
    identityId: string,
  ): Promise<WitnessReceipt[]> {
    const current = await readJsonFile<WitnessReceipt[]>(
      join(this.baseDir, "witness", `${identityId}.json`),
    );
    return current ?? [];
  }
}
