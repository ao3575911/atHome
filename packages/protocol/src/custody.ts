import { generateEd25519KeyPair, signCanonicalPayload } from "./crypto.js";
import type {
  KeyPurpose,
  KeyStatus,
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

function publicKeyView(key: PrivateKeyMaterial): PublicKey {
  const { privateKey: _privateKey, ...publicMaterial } = key;
  return publicMaterial;
}

export class LocalDevKeyCustodyProvider implements KeyCustodyProvider {
  private readonly keys = new Map<string, PrivateKeyMaterial>();

  constructor(
    private readonly options: { allowPrivateKeyExport?: boolean } = {},
  ) {}

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
    return publicKeyView(material);
  }

  async sign(input: SignInput): Promise<string> {
    const key = this.requireKey(input.identityId, input.keyId);
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
}

export function createLocalDevKeyCustody(
  options: { allowPrivateKeyExport?: boolean } = {},
): KeyCustodyProvider {
  return new LocalDevKeyCustodyProvider(options);
}

export function createMemoryKeyCustodyProvider(
  options: { allowPrivateKeyExport?: boolean } = {},
): KeyCustodyProvider {
  return createLocalDevKeyCustody(options);
}
