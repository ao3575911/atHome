import { generateEd25519KeyPair, signCanonicalPayload } from "./crypto.js";
import type {
  CustodyKeyRecord,
  KeyPurpose,
  KeyStatus,
  PrivateIdentityRecord,
  PrivateKeyMaterial,
  PublicKey,
} from "./types.js";

export interface ProvisionKeyInput {
  identityId: string;
  keyId: string;
  purpose: KeyPurpose;
}

export interface RotateKeyInput {
  identityId: string;
  keyId: string;
  newKeyId: string;
}

export interface SignInput {
  identityId: string;
  keyId: string;
  payload: unknown;
}

export interface ExportPrivateKeyInput {
  identityId: string;
  keyId: string;
}

export interface RotateKeyResult {
  previous: PublicKey;
  current: PublicKey;
}

export interface KeyCustodyProvider {
  provisionKey(input: ProvisionKeyInput): Promise<PublicKey>;
  sign(input: SignInput): Promise<string>;
  rotateKey(input: RotateKeyInput): Promise<RotateKeyResult>;
  exportPrivateKey(input: ExportPrivateKeyInput): Promise<string>;
}

export interface KeyCustodyRecordStore {
  readCustodyKeyRecord(
    identityId: string,
    keyId: string,
  ): Promise<CustodyKeyRecord | null>;
  writeCustodyKeyRecord(record: CustodyKeyRecord): Promise<void>;
  listCustodyKeyRecords(identityId: string): Promise<CustodyKeyRecord[]>;
  readPrivateRecord?(identityId: string): Promise<PrivateIdentityRecord | null>;
}

function publicKeyView(key: PrivateKeyMaterial): PublicKey {
  const { privateKey: _privateKey, ...publicMaterial } = key;
  return publicMaterial;
}

function custodyRecordFromKey(input: {
  identityId: string;
  key: PrivateKeyMaterial;
  provider: CustodyKeyRecord["provider"];
  exportable: boolean;
}): CustodyKeyRecord {
  return {
    identityId: input.identityId,
    keyId: input.key.id,
    provider: input.provider,
    publicKeyId: input.key.id,
    purpose: input.key.purpose,
    status: input.key.status,
    createdAt: input.key.createdAt,
    updatedAt:
      input.key.deactivatedAt ?? input.key.revokedAt ?? input.key.createdAt,
    deactivatedAt: input.key.deactivatedAt,
    revokedAt: input.key.revokedAt,
    exportable: input.exportable,
  };
}

export class LocalDevKeyCustodyProvider implements KeyCustodyProvider {
  private readonly keys = new Map<string, PrivateKeyMaterial>();
  private readonly recordStore?: KeyCustodyRecordStore | undefined;
  private readonly provider: CustodyKeyRecord["provider"];

  constructor(
    private readonly options: {
      allowPrivateKeyExport?: boolean;
      recordStore?: KeyCustodyRecordStore | undefined;
      provider?: CustodyKeyRecord["provider"] | undefined;
    } = {},
  ) {
    this.recordStore = options.recordStore;
    this.provider = options.provider ?? "local-dev";
  }

  async provisionKey(input: ProvisionKeyInput): Promise<PublicKey> {
    const now = new Date().toISOString();
    const keyPair = generateEd25519KeyPair();
    const material: PrivateKeyMaterial = {
      id: input.keyId,
      type: "ed25519",
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      purpose: input.purpose,
      status: "active",
      createdAt: now,
    };

    this.keys.set(this.keyScope(input.identityId, input.keyId), material);
    await this.persistCustodyRecord(input.identityId, material);
    return publicKeyView(material);
  }

  async sign(input: SignInput): Promise<string> {
    let key = this.keys.get(this.keyScope(input.identityId, input.keyId));

    if (!key && this.recordStore?.readPrivateRecord) {
      const record = await this.recordStore.readPrivateRecord(input.identityId);
      const stored = record?.keys?.[input.keyId];
      if (stored) {
        this.keys.set(this.keyScope(input.identityId, input.keyId), stored);
        key = stored;
      }
    }

    if (!key) {
      throw new Error(`Unknown key: ${input.identityId}:${input.keyId}`);
    }

    return signCanonicalPayload(input.payload, key.privateKey);
  }

  async rotateKey(input: RotateKeyInput): Promise<RotateKeyResult> {
    const previous = this.requireKey(input.identityId, input.keyId);
    const now = new Date().toISOString();
    const previousMaterial: PrivateKeyMaterial = {
      ...previous,
      status: "deprecated",
      deactivatedAt: now,
    };

    this.keys.set(
      this.keyScope(input.identityId, input.keyId),
      previousMaterial,
    );
    await this.persistCustodyRecord(input.identityId, previousMaterial);

    const nextKey = await this.provisionKey({
      identityId: input.identityId,
      keyId: input.newKeyId,
      purpose: previous.purpose,
    });

    return { previous: publicKeyView(previousMaterial), current: nextKey };
  }

  async exportPrivateKey(input: ExportPrivateKeyInput): Promise<string> {
    if (!this.isExportAllowed()) {
      throw new Error("Private key export is disabled");
    }

    return this.requireKey(input.identityId, input.keyId).privateKey;
  }

  private requireKey(identityId: string, keyId: string): PrivateKeyMaterial {
    const key = this.keys.get(this.keyScope(identityId, keyId));
    if (!key) {
      throw new Error(`Unknown key: ${identityId}:${keyId}`);
    }

    return key;
  }

  private keyScope(identityId: string, keyId: string): string {
    return `${identityId}:${keyId}`;
  }

  private isExportAllowed(): boolean {
    if (process.env.NODE_ENV === "production") {
      return false;
    }

    return this.options.allowPrivateKeyExport === true;
  }

  private async persistCustodyRecord(
    identityId: string,
    key: PrivateKeyMaterial,
  ): Promise<void> {
    if (!this.recordStore) {
      return;
    }

    await this.recordStore.writeCustodyKeyRecord(
      custodyRecordFromKey({
        identityId,
        key,
        provider: this.provider,
        exportable: this.options.allowPrivateKeyExport === true,
      }),
    );
  }
}

export function createLocalDevKeyCustody(
  options: {
    allowPrivateKeyExport?: boolean;
    recordStore?: KeyCustodyRecordStore | undefined;
    provider?: CustodyKeyRecord["provider"] | undefined;
  } = {},
): KeyCustodyProvider {
  return new LocalDevKeyCustodyProvider(options);
}

export function createMemoryKeyCustodyProvider(
  options: {
    allowPrivateKeyExport?: boolean;
    recordStore?: KeyCustodyRecordStore | undefined;
    provider?: CustodyKeyRecord["provider"] | undefined;
  } = {},
): KeyCustodyProvider {
  return createLocalDevKeyCustody(options);
}
