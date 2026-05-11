import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface RevocationEntry {
  id: string;
  revokedAt: string;
  reason?: string | undefined;
}

interface IdentityRevocationBucket {
  agents: Record<string, RevocationEntry>;
  tokens: Record<string, RevocationEntry>;
  keys: Record<string, RevocationEntry>;
}

interface RevocationState {
  identities: Record<string, IdentityRevocationBucket>;
}

function emptyBucket(): IdentityRevocationBucket {
  return { agents: {}, tokens: {}, keys: {} };
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
  await mkdir(dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await rename(tempPath, filePath);
}

export class ApiRevocationStore {
  constructor(private readonly baseDir: string) {}

  private path(): string {
    return join(this.baseDir, "revocations.json");
  }

  private async readState(): Promise<RevocationState> {
    const current = (await readJsonFile<RevocationState>(this.path())) ?? {
      identities: {},
    };
    return {
      identities: current.identities ?? {},
    };
  }

  private async writeState(state: RevocationState): Promise<void> {
    await writeJsonFile(this.path(), state);
  }

  private async getBucket(
    identityId: string,
  ): Promise<IdentityRevocationBucket> {
    const state = await this.readState();
    return state.identities[identityId] ?? emptyBucket();
  }

  private async updateBucket(
    identityId: string,
    updater: (bucket: IdentityRevocationBucket) => IdentityRevocationBucket,
  ): Promise<IdentityRevocationBucket> {
    const state = await this.readState();
    const bucket = state.identities[identityId] ?? emptyBucket();
    const nextBucket = updater(bucket);
    state.identities[identityId] = nextBucket;
    await this.writeState(state);
    return nextBucket;
  }

  async isAgentRevoked(identityId: string, agentId: string): Promise<boolean> {
    const bucket = await this.getBucket(identityId);
    return bucket.agents[agentId] !== undefined;
  }

  async isTokenRevoked(identityId: string, tokenId: string): Promise<boolean> {
    const bucket = await this.getBucket(identityId);
    return bucket.tokens[tokenId] !== undefined;
  }

  async isKeyRevoked(identityId: string, keyId: string): Promise<boolean> {
    const bucket = await this.getBucket(identityId);
    return bucket.keys[keyId] !== undefined;
  }

  async revokeAgent(
    identityId: string,
    agentId: string,
    reason?: string,
  ): Promise<RevocationEntry> {
    const revokedAt = new Date().toISOString();
    const entry = { id: agentId, revokedAt, reason };
    await this.updateBucket(identityId, (bucket) => ({
      ...bucket,
      agents: { ...bucket.agents, [agentId]: entry },
    }));
    return entry;
  }

  async revokeToken(
    identityId: string,
    tokenId: string,
    reason?: string,
  ): Promise<RevocationEntry> {
    const revokedAt = new Date().toISOString();
    const entry = { id: tokenId, revokedAt, reason };
    await this.updateBucket(identityId, (bucket) => ({
      ...bucket,
      tokens: { ...bucket.tokens, [tokenId]: entry },
    }));
    return entry;
  }

  async revokeKey(
    identityId: string,
    keyId: string,
    reason?: string,
  ): Promise<RevocationEntry> {
    const revokedAt = new Date().toISOString();
    const entry = { id: keyId, revokedAt, reason };
    await this.updateBucket(identityId, (bucket) => ({
      ...bucket,
      keys: { ...bucket.keys, [keyId]: entry },
    }));
    return entry;
  }
}
