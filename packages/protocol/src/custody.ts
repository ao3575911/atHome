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

// ---------------------------------------------------------------------------
// PasskeyKeyCustodyProvider
// ---------------------------------------------------------------------------
// Signing is delegated to a caller-provided WebAuthn assertion callback.
// Raw private keys never exist in this provider — no exportPrivateKey support.

export interface PasskeyAssertionInput {
  identityId: string;
  keyId: string;
  challenge: Uint8Array;
}

export interface PasskeyAssertion {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
}

export interface PasskeyKeyCustodyProviderOptions {
  identityId: string;
  credentialId: string;
  publicKey: string;
  requestAssertion(input: PasskeyAssertionInput): Promise<PasskeyAssertion>;
  recordStore?: KeyCustodyRecordStore | undefined;
}

export class PasskeyKeyCustodyProvider implements KeyCustodyProvider {
  private readonly options: PasskeyKeyCustodyProviderOptions;

  constructor(options: PasskeyKeyCustodyProviderOptions) {
    this.options = options;
  }

  async provisionKey(input: ProvisionKeyInput): Promise<PublicKey> {
    const now = new Date().toISOString();
    const record: CustodyKeyRecord = {
      identityId: input.identityId,
      keyId: input.keyId,
      provider: "passkey",
      publicKeyId: this.options.credentialId,
      purpose: input.purpose,
      status: "active",
      createdAt: now,
      updatedAt: now,
      exportable: false,
      metadata: { credentialId: this.options.credentialId },
    };

    await this.options.recordStore?.writeCustodyKeyRecord(record);

    return {
      id: input.keyId,
      type: "ed25519",
      publicKey: this.options.publicKey,
      purpose: input.purpose,
      status: "active",
      createdAt: now,
    };
  }

  async sign(input: SignInput): Promise<string> {
    const canonical = JSON.stringify(input.payload);
    const challenge = new TextEncoder().encode(canonical);

    const assertion = await this.options.requestAssertion({
      identityId: input.identityId,
      keyId: input.keyId,
      challenge,
    });

    // Return the assertion signature as base64 for use in mutation auth headers.
    // Consumers must verify the WebAuthn assertion envelope separately.
    return btoa(String.fromCharCode(...assertion.signature));
  }

  async rotateKey(input: RotateKeyInput): Promise<RotateKeyResult> {
    // Passkey rotation is managed by the passkey provider (authenticator).
    // The caller should provision a new credential and call provisionKey on the new provider.
    throw new Error(
      `Passkey key rotation for ${input.identityId}:${input.keyId} must be performed by re-enrolling a new passkey credential`,
    );
  }

  async exportPrivateKey(_input: ExportPrivateKeyInput): Promise<string> {
    throw new Error("PasskeyKeyCustodyProvider does not export private keys");
  }
}

export function createPasskeyKeyCustodyProvider(
  options: PasskeyKeyCustodyProviderOptions,
): KeyCustodyProvider {
  return new PasskeyKeyCustodyProvider(options);
}

// ---------------------------------------------------------------------------
// HsmKeyCustodyProvider interface + KMS skeleton
// ---------------------------------------------------------------------------
// Raw private keys are never exported from HSM-backed providers.
// Implementors wire `provisionKey` and `sign` to their KMS/HSM SDK calls.

export interface HsmProvisionKeyResult {
  keyId: string;
  publicKey: string;
  keyArn?: string | undefined;
  resourceName?: string | undefined;
}

export interface HsmKeyCustodyProvider {
  readonly providerName: string;
  provisionKey(input: ProvisionKeyInput): Promise<HsmProvisionKeyResult>;
  sign(input: SignInput): Promise<string>;
  rotateKey(input: RotateKeyInput): Promise<RotateKeyResult>;
  // exportPrivateKey is intentionally absent — HSM keys never leave the HSM.
  describeKey(
    identityId: string,
    keyId: string,
  ): Promise<HsmProvisionKeyResult | null>;
}

/**
 * Reference skeleton for AWS KMS or GCP Cloud KMS.
 * Wire `kmsSign` to your KMS SDK (e.g. `@aws-sdk/client-kms` SignCommand).
 * Wire `kmsProvision` to CreateKey / GetPublicKey.
 * Wire `kmsDescribe` to DescribeKey / GetKeyMetadata.
 */
export interface KmsAdapterOptions {
  providerName: string;
  kmsProvision(input: {
    identityId: string;
    keyId: string;
    purpose: KeyPurpose;
  }): Promise<HsmProvisionKeyResult>;
  kmsSign(input: {
    identityId: string;
    keyId: string;
    payload: unknown;
  }): Promise<string>;
  kmsDescribe(
    identityId: string,
    keyId: string,
  ): Promise<HsmProvisionKeyResult | null>;
  recordStore?: KeyCustodyRecordStore | undefined;
}

export class KmsKeyCustodyAdapter implements HsmKeyCustodyProvider {
  readonly providerName: string;
  private readonly options: KmsAdapterOptions;

  constructor(options: KmsAdapterOptions) {
    this.providerName = options.providerName;
    this.options = options;
  }

  async provisionKey(input: ProvisionKeyInput): Promise<HsmProvisionKeyResult> {
    const result = await this.options.kmsProvision(input);
    const now = new Date().toISOString();
    await this.options.recordStore?.writeCustodyKeyRecord({
      identityId: input.identityId,
      keyId: input.keyId,
      provider: this.providerName,
      publicKeyId: result.keyId,
      purpose: input.purpose,
      status: "active",
      createdAt: now,
      updatedAt: now,
      exportable: false,
      metadata: {
        keyArn: result.keyArn,
        resourceName: result.resourceName,
      },
    });
    return result;
  }

  async sign(input: SignInput): Promise<string> {
    return this.options.kmsSign(input);
  }

  async rotateKey(input: RotateKeyInput): Promise<RotateKeyResult> {
    const previous = await this.describeKey(input.identityId, input.keyId);
    if (!previous) {
      throw new Error(`Unknown KMS key: ${input.identityId}:${input.keyId}`);
    }
    const now = new Date().toISOString();
    await this.options.recordStore?.writeCustodyKeyRecord({
      identityId: input.identityId,
      keyId: input.keyId,
      provider: this.providerName,
      publicKeyId: previous.keyId,
      purpose: "root",
      status: "deprecated",
      createdAt: now,
      updatedAt: now,
      deactivatedAt: now,
      exportable: false,
    });
    const next = await this.provisionKey({
      identityId: input.identityId,
      keyId: input.newKeyId,
      purpose: "root",
    });
    return {
      previous: {
        id: input.keyId,
        type: "ed25519",
        publicKey: previous.publicKey,
        purpose: "root",
        status: "deprecated",
        createdAt: now,
        deactivatedAt: now,
      },
      current: {
        id: input.newKeyId,
        type: "ed25519",
        publicKey: next.publicKey,
        purpose: "root",
        status: "active",
        createdAt: now,
      },
    };
  }

  async describeKey(
    identityId: string,
    keyId: string,
  ): Promise<HsmProvisionKeyResult | null> {
    return this.options.kmsDescribe(identityId, keyId);
  }
}

export function createKmsKeyCustodyAdapter(
  options: KmsAdapterOptions,
): KmsKeyCustodyAdapter {
  return new KmsKeyCustodyAdapter(options);
}
