import { randomUUID } from "node:crypto";
import { canonicalize } from "./canonical.js";
import {
  generateEd25519KeyPair,
  sha256,
  signCanonicalPayload,
  verifyCanonicalPayload,
} from "./crypto.js";
import type { RegistryEvent } from "./events.js";
import type { WitnessReceipt, VerificationOutcome } from "./types.js";
import { registryEventHash } from "./backend.js";

export interface WitnessReceiptContext {
  identityId: string;
  logIndex: number;
}

export interface WitnessService {
  issueReceipt(
    event: RegistryEvent,
    context: WitnessReceiptContext,
  ): Promise<WitnessReceipt>;
  verifyReceipt(
    event: RegistryEvent,
    receipt: WitnessReceipt,
  ): Promise<VerificationOutcome>;
}

function eventKind(eventType: RegistryEvent["type"]): WitnessReceipt["kind"] {
  if (eventType === "agent.revoked") {
    return "agent";
  }

  if (eventType === "token.revoked") {
    return "token";
  }

  return "key";
}

function receiptDraft(
  receipt: WitnessReceipt,
): Omit<WitnessReceipt, "signature"> {
  const { signature: _signature, ...draft } = receipt;
  return draft;
}

export class LocalWitnessService implements WitnessService {
  private readonly publicKey: string;
  private readonly privateKey: string;
  private readonly witnessKeyId: string;
  private readonly receipts = new Map<string, WitnessReceipt>();

  constructor(options: { witnessKeyId?: string } = {}) {
    const keyPair = generateEd25519KeyPair();
    this.publicKey = keyPair.publicKey;
    this.privateKey = keyPair.privateKey;
    this.witnessKeyId = options.witnessKeyId ?? "witness";
  }

  async issueReceipt(
    event: RegistryEvent,
    context: WitnessReceiptContext,
  ): Promise<WitnessReceipt> {
    const receipt: WitnessReceipt = {
      receiptId: randomUUID().replaceAll("-", ""),
      identityId: context.identityId,
      eventId: event.id,
      eventHash: event.hash ?? registryEventHash(event),
      kind: eventKind(event.type),
      subjectId: event.subjectId,
      revokedAt: event.timestamp,
      payloadHash: event.payloadHash,
      logIndex: context.logIndex,
      witnessKeyId: this.witnessKeyId,
      signature: "",
    };

    const signed = {
      ...receipt,
      signature: signCanonicalPayload(receiptDraft(receipt), this.privateKey),
    };

    this.receipts.set(signed.receiptId, signed);
    return signed;
  }

  async verifyReceipt(
    event: RegistryEvent,
    receipt: WitnessReceipt,
  ): Promise<VerificationOutcome> {
    const expectedEventHash = event.hash ?? registryEventHash(event);
    if (
      receipt.identityId !== event.identityId ||
      receipt.eventId !== event.id ||
      receipt.eventHash !== expectedEventHash ||
      receipt.subjectId !== event.subjectId ||
      receipt.revokedAt !== event.timestamp ||
      receipt.payloadHash !== event.payloadHash ||
      receipt.kind !== eventKind(event.type)
    ) {
      return {
        ok: false,
        code: "witness_receipt_invalid",
        reason: "Witness receipt does not match event payload",
      };
    }

    const valid = verifyCanonicalPayload(
      receiptDraft(receipt),
      receipt.signature,
      this.publicKey,
    );
    if (!valid) {
      return {
        ok: false,
        code: "witness_receipt_invalid",
        reason: "Witness receipt signature is invalid",
      };
    }

    return { ok: true };
  }

  async listReceipts(): Promise<WitnessReceipt[]> {
    return [...this.receipts.values()].map(
      (receipt) => JSON.parse(JSON.stringify(receipt)) as WitnessReceipt,
    );
  }
}

export function createLocalWitnessService(
  options: { witnessKeyId?: string } = {},
): WitnessService {
  return new LocalWitnessService(options);
}

export function createMemoryWitnessService(
  options: { witnessKeyId?: string } = {},
): WitnessService {
  return createLocalWitnessService(options);
}

export function createWitnessReceiptDigest(receipt: WitnessReceipt): string {
  return sha256(canonicalize(receiptDraft(receipt)));
}
