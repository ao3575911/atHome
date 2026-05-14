import { randomUUID } from "node:crypto";
import { canonicalize } from "./canonical.js";
import { sha256, signCanonicalPayload } from "./crypto.js";
import type { RevocationRecord, RevokedEntry } from "./types.js";

export type RegistryEventType =
  | "identity.created"
  | "service.added"
  | "agent.added"
  | "agent.revoked"
  | "key.added"
  | "key.deprecated"
  | "key.revoked"
  | "token.issued"
  | "token.revoked"
  | "identity.rotated"
  | "namespace.reserved"
  | "namespace.suspended"
  | "namespace.restored"
  | "namespace.transferred"
  | "namespace.recovered";

export interface RegistryEventDraft {
  id: string;
  type: RegistryEventType;
  subjectId: string;
  timestamp: string;
  signerKeyId: string;
  previousHash: string;
  payloadHash: string;
  details?: Record<string, unknown> | undefined;
}

export interface RegistryEvent extends RegistryEventDraft {
  identityId?: string | undefined;
  hash?: string | undefined;
  signature: string;
}

export function createRegistryEventDraft(input: {
  type: RegistryEventType;
  subjectId: string;
  signerKeyId: string;
  previousHash: string;
  details?: Record<string, unknown> | undefined;
  timestamp?: string | undefined;
}): RegistryEventDraft {
  const timestamp = input.timestamp ?? new Date().toISOString();
  const details = input.details ?? {};
  const payloadHash = sha256(
    canonicalize({
      type: input.type,
      subjectId: input.subjectId,
      signerKeyId: input.signerKeyId,
      previousHash: input.previousHash,
      timestamp,
      details,
    }),
  );

  return {
    id: randomUUID().replaceAll("-", ""),
    type: input.type,
    subjectId: input.subjectId,
    timestamp,
    signerKeyId: input.signerKeyId,
    previousHash: input.previousHash,
    payloadHash,
    details: Object.keys(details).length > 0 ? details : undefined,
  };
}

export function signRegistryEvent(
  draft: RegistryEventDraft,
  privateKey: string,
): RegistryEvent {
  return {
    ...draft,
    signature: signCanonicalPayload(draft, privateKey),
  };
}

export function toRegistryEventDraft(event: RegistryEvent): RegistryEventDraft {
  const {
    signature: _signature,
    identityId: _identityId,
    hash: _hash,
    ...draft
  } = event;
  return draft;
}

export function materializeRegistryEvent(
  identityId: string,
  event: RegistryEvent,
  previousHash: string,
): RegistryEvent {
  if (event.previousHash !== previousHash) {
    throw new Error(`Registry event previous hash mismatch for ${identityId}`);
  }

  const hash = sha256(
    canonicalize({
      identityId,
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

  return {
    ...event,
    identityId,
    hash,
  };
}

export function applyRegistryEventToRevocationRecord(
  record: RevocationRecord,
  event: RegistryEvent,
): RevocationRecord {
  const next: RevocationRecord = {
    ...record,
    revokedAgents: { ...record.revokedAgents },
    revokedCapabilityTokens: { ...record.revokedCapabilityTokens },
    revokedPublicKeys: { ...record.revokedPublicKeys },
    updatedAt: event.timestamp,
  };

  const entry: RevokedEntry = {
    revokedAt: event.timestamp,
    reason:
      typeof event.details?.reason === "string"
        ? event.details.reason
        : undefined,
  };

  if (event.type === "agent.revoked") {
    next.revokedAgents[event.subjectId] = entry;
  } else if (event.type === "token.revoked") {
    next.revokedCapabilityTokens[event.subjectId] = entry;
  } else if (event.type === "key.revoked") {
    next.revokedPublicKeys[event.subjectId] = entry;
  }

  return next;
}
