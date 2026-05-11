import type { RevocationRecord, RevokedEntry } from "./types.js";

export function createEmptyRevocationRecord(
  id: string,
  updatedAt: string,
): RevocationRecord {
  return {
    id,
    revokedAgents: {},
    revokedCapabilityTokens: {},
    revokedPublicKeys: {},
    updatedAt,
  };
}

export function revokeEntry(
  record: RevocationRecord,
  category: "agents" | "tokens" | "keys",
  id: string,
  entry: RevokedEntry,
): RevocationRecord {
  const next: RevocationRecord = {
    ...record,
    revokedAgents: { ...record.revokedAgents },
    revokedCapabilityTokens: { ...record.revokedCapabilityTokens },
    revokedPublicKeys: { ...record.revokedPublicKeys },
    updatedAt: entry.revokedAt,
  };

  if (category === "agents") {
    next.revokedAgents[id] = entry;
  } else if (category === "tokens") {
    next.revokedCapabilityTokens[id] = entry;
  } else {
    next.revokedPublicKeys[id] = entry;
  }

  return next;
}

export function isRevoked(
  record: RevocationRecord,
  category: "agents" | "tokens" | "keys",
  id: string,
): boolean {
  if (category === "agents") {
    return record.revokedAgents[id] !== undefined;
  }

  if (category === "tokens") {
    return record.revokedCapabilityTokens[id] !== undefined;
  }

  return record.revokedPublicKeys[id] !== undefined;
}
