import { canonicalize } from "./canonical.js";
import { verifyCanonicalPayload } from "./crypto.js";
import { mcoOfferDraftSchema, mcoOfferSchema } from "./schemas.js";
import { findPublicKey } from "./signatures.js";
import type {
  AuthorizationFailureCode,
  IdentityManifest,
  McoCall,
  McoMesh,
  McoMeshEdge,
  McoMethod,
  McoOffer,
  McoOfferDraft,
  VerificationOutcome,
  VerifiedClaim,
} from "./types.js";
import { MCO_METHODS, MCO_OFFER_VERSION } from "./types.js";

export const MCO_CLAIM_TYPE = "mco.offer";
export const MCO_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MCO_MIN_TTL_SECONDS = 60;
export const MCO_MAX_TTL_SECONDS = 365 * 24 * 60 * 60;

const SERVICE_ID = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/;
const CALL_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const CALL_PATH = /^\/[^\s?#]{0,199}$/;
const PERMISSION = /^[^\s]{1,128}$/;

export class McoError extends Error {
  readonly code: "mco_invalid" | "mco_not_found" | "service_not_found";

  constructor(
    code: "mco_invalid" | "mco_not_found" | "service_not_found",
    message: string,
  ) {
    super(message);
    this.name = "McoError";
    this.code = code;
  }
}

export interface PublishMcoOfferInput {
  serviceId: string;
  calls: Array<{
    id: string;
    method: string;
    path: string;
    permission: string;
    delegatesTo?: string[] | undefined;
  }>;
  ttlSeconds?: number | undefined;
  now?: string | undefined;
}

export function mcoClaimId(serviceId: string): string {
  return `${serviceId}#mco`;
}

export function prepareMcoOfferDraft(
  manifest: IdentityManifest,
  input: PublishMcoOfferInput,
): McoOfferDraft {
  if (!SERVICE_ID.test(input.serviceId)) {
    throw new McoError(
      "mco_invalid",
      `MCO service id is invalid: ${input.serviceId}`,
    );
  }

  if (!manifest.services.some((service) => service.id === input.serviceId)) {
    throw new McoError(
      "service_not_found",
      `MCO service is not registered: ${input.serviceId}`,
    );
  }

  const ttl = input.ttlSeconds ?? MCO_DEFAULT_TTL_SECONDS;
  if (
    !Number.isInteger(ttl) ||
    ttl < MCO_MIN_TTL_SECONDS ||
    ttl > MCO_MAX_TTL_SECONDS
  ) {
    throw new McoError(
      "mco_invalid",
      `MCO ttlSeconds is outside ${MCO_MIN_TTL_SECONDS}..${MCO_MAX_TTL_SECONDS}`,
    );
  }

  const issuedAt = input.now ?? new Date().toISOString();
  const issuedAtMs = Date.parse(issuedAt);
  if (Number.isNaN(issuedAtMs)) {
    throw new McoError("mco_invalid", "MCO issuedAt is not a timestamp");
  }

  if (input.calls.length === 0) {
    throw new McoError("mco_invalid", "MCO offer must include a call");
  }

  if (input.calls.length > 32) {
    throw new McoError("mco_invalid", "MCO offer has too many calls");
  }

  const calls = input.calls.map((call) =>
    normalizeCall(manifest, input.serviceId, call),
  );
  const seenIds = new Set<string>();
  const seenGrants = new Set<string>();
  for (const call of calls) {
    if (seenIds.has(call.id)) {
      throw new McoError("mco_invalid", `MCO duplicate call: ${call.id}`);
    }
    seenIds.add(call.id);
    const grant = `${call.method}\u0000${call.path}\u0000${call.permission}`;
    if (seenGrants.has(grant)) {
      throw new McoError(
        "mco_invalid",
        `MCO duplicate call: ${call.method} ${call.path} ${call.permission}`,
      );
    }
    seenGrants.add(grant);
  }
  calls.sort((left, right) => left.id.localeCompare(right.id));

  const draft: McoOfferDraft = {
    version: MCO_OFFER_VERSION,
    id: `${input.serviceId}#${issuedAt}`,
    issuer: manifest.id,
    serviceId: input.serviceId,
    calls,
    issuedAt,
    expiresAt: new Date(issuedAtMs + ttl * 1000).toISOString(),
    signatureKeyId: manifest.signatureKeyId,
  };

  const parsed = mcoOfferDraftSchema.safeParse(draft);
  if (!parsed.success) {
    throw new McoError("mco_invalid", "MCO offer is malformed");
  }

  const existing = readMcoOffers(manifest).filter(
    (offer) => offer.serviceId !== input.serviceId,
  );
  assertAcyclic([...existing, parsed.data]);
  return parsed.data;
}

export function verifyMcoOffer(
  offer: McoOffer,
  manifest: IdentityManifest,
): VerificationOutcome {
  const parsed = mcoOfferSchema.safeParse(offer);
  if (!parsed.success) {
    return deny("mco_offer_invalid", "MCO offer is malformed");
  }

  if (parsed.data.issuer !== manifest.id) {
    return deny("mco_offer_invalid", "MCO offer issuer does not match");
  }

  const key = findPublicKey(manifest, parsed.data.signatureKeyId);
  if (!key) {
    return deny(
      "key_not_found",
      `Signature key not found: ${parsed.data.signatureKeyId}`,
    );
  }

  if (key.purpose !== "root") {
    return deny(
      "mco_offer_invalid",
      "MCO offer must be signed by the root key",
    );
  }

  switch (key.status) {
    case "active":
    case "deprecated":
      break;
    case "revoked":
      return deny("key_revoked", `Signature key revoked: ${key.id}`);
    default: {
      const unreachable: never = key.status;
      return deny("mco_offer_invalid", unreachable);
    }
  }

  const { signature, ...draft } = parsed.data;
  if (!verifyCanonicalPayload(draft, signature, key.publicKey)) {
    return deny("mco_offer_invalid", "MCO offer signature is invalid");
  }

  return { ok: true };
}

export function authorizeMcoCall(input: {
  offer: McoOffer;
  method: string;
  path: string;
  permission: string;
  delegateServiceId?: string | undefined;
  now?: string | undefined;
}): VerificationOutcome {
  const parsed = mcoOfferSchema.safeParse(input.offer);
  if (!parsed.success) {
    return deny("mco_offer_invalid", "MCO offer is malformed");
  }

  const offer = parsed.data;
  const nowMs = Date.parse(input.now ?? new Date().toISOString());
  if (Number.isNaN(nowMs)) {
    return deny("mco_offer_invalid", "MCO decision time is not a timestamp");
  }

  if (nowMs < Date.parse(offer.issuedAt)) {
    return deny("mco_offer_not_active", "MCO offer is not active yet");
  }

  if (nowMs >= Date.parse(offer.expiresAt)) {
    return deny("mco_offer_expired", "MCO offer is expired");
  }

  const method = input.method.toUpperCase();
  const routes = offer.calls.filter(
    (entry) => entry.method === method && entry.path === input.path,
  );
  if (routes.length === 0) {
    return deny("mco_call_not_offered", "MCO call is not on the offer", {
      serviceId: offer.serviceId,
      method,
      path: input.path,
    });
  }

  const permitted = routes.filter(
    (entry) => entry.permission === input.permission,
  );
  if (permitted.length === 0) {
    const details: Record<string, unknown> = {
      serviceId: offer.serviceId,
      permission: input.permission,
    };
    if (routes.length === 1 && routes[0]) {
      details.callId = routes[0].id;
    }
    return deny(
      "mco_permission_mismatch",
      "MCO call permission does not match the offer",
      details,
    );
  }

  const delegate = input.delegateServiceId?.trim() ?? "";
  if (delegate.length > 0) {
    const call = permitted.find((entry) =>
      entry.delegatesTo.includes(delegate),
    );
    if (!call) {
      const details: Record<string, unknown> = {
        serviceId: offer.serviceId,
        delegateServiceId: delegate,
      };
      if (permitted.length === 1 && permitted[0]) {
        details.callId = permitted[0].id;
      }
      return deny(
        "mco_delegation_not_offered",
        "MCO delegation is not on the offer",
        details,
      );
    }
  }

  return { ok: true };
}

export function embedMcoOffer(
  manifest: IdentityManifest,
  offer: McoOffer,
): IdentityManifest {
  const claim: VerifiedClaim = {
    id: mcoClaimId(offer.serviceId),
    type: MCO_CLAIM_TYPE,
    value: canonicalize(offer),
    issuer: manifest.id,
    verifiedAt: offer.issuedAt,
  };

  return {
    ...manifest,
    claims: [
      ...manifest.claims.filter((entry) => entry.id !== claim.id),
      claim,
    ],
  };
}

export function removeMcoOffer(
  manifest: IdentityManifest,
  serviceId: string,
): IdentityManifest {
  const claimId = mcoClaimId(serviceId);
  if (!manifest.claims.some((entry) => entry.id === claimId)) {
    throw new McoError("mco_not_found", `MCO offer not found: ${serviceId}`);
  }

  return {
    ...manifest,
    claims: manifest.claims.filter((entry) => entry.id !== claimId),
  };
}

export function readMcoOffers(manifest: IdentityManifest): McoOffer[] {
  const offers: McoOffer[] = [];
  for (const claim of manifest.claims) {
    if (claim.type !== MCO_CLAIM_TYPE) {
      continue;
    }
    offers.push(parseMcoOfferClaim(claim.value, manifest));
  }

  offers.sort((left, right) => left.serviceId.localeCompare(right.serviceId));
  return offers;
}

export function projectMcoMesh(manifest: IdentityManifest): McoMesh {
  const offers = readMcoOffers(manifest);
  return {
    identityId: manifest.id,
    offers,
    edges: meshEdges(offers),
  };
}

function parseMcoOfferClaim(
  value: string,
  manifest: IdentityManifest,
): McoOffer {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new McoError("mco_invalid", "MCO offer claim is not JSON");
  }

  const offer = mcoOfferSchema.safeParse(parsed);
  if (!offer.success) {
    throw new McoError("mco_invalid", "MCO offer is malformed");
  }

  const verification = verifyMcoOffer(offer.data, manifest);
  if (!verification.ok) {
    throw new McoError(
      "mco_invalid",
      verification.reason ?? "MCO offer signature is invalid",
    );
  }

  return offer.data;
}

function normalizeCall(
  manifest: IdentityManifest,
  serviceId: string,
  call: PublishMcoOfferInput["calls"][number],
): McoCall {
  if (!CALL_ID.test(call.id)) {
    throw new McoError("mco_invalid", `MCO call id is invalid: ${call.id}`);
  }

  const method = call.method.toUpperCase();
  if (!isMcoMethod(method)) {
    throw new McoError(
      "mco_invalid",
      `MCO call method is not supported: ${call.method}`,
    );
  }

  if (!CALL_PATH.test(call.path)) {
    throw new McoError(
      "mco_invalid",
      `MCO call path must start with /: ${call.path}`,
    );
  }

  if (!PERMISSION.test(call.permission)) {
    throw new McoError(
      "mco_invalid",
      `MCO call permission is invalid: ${call.permission}`,
    );
  }

  const delegates = call.delegatesTo ?? [];
  if (delegates.length > 8) {
    throw new McoError(
      "mco_invalid",
      `MCO call has too many delegates: ${call.id}`,
    );
  }

  const unique: string[] = [];
  for (const target of delegates) {
    if (!SERVICE_ID.test(target)) {
      throw new McoError(
        "mco_invalid",
        `MCO delegation target is invalid: ${target}`,
      );
    }
    if (target === serviceId) {
      throw new McoError(
        "mco_invalid",
        `MCO call cannot delegate to its own service: ${serviceId}`,
      );
    }
    if (!manifest.services.some((service) => service.id === target)) {
      throw new McoError(
        "service_not_found",
        `MCO delegation target is not a registered service: ${target}`,
      );
    }
    if (!unique.includes(target)) {
      unique.push(target);
    }
  }
  unique.sort((left, right) => left.localeCompare(right));

  return {
    id: call.id,
    method,
    path: call.path,
    permission: call.permission,
    delegatesTo: unique,
  };
}

function assertAcyclic(offers: McoOfferDraft[]): void {
  const graph = new Map<string, string[]>();
  for (const offer of offers) {
    const targets = new Set<string>();
    for (const call of offer.calls) {
      for (const target of call.delegatesTo) {
        targets.add(target);
      }
    }
    graph.set(offer.serviceId, [...targets].sort());
  }

  for (const targets of graph.values()) {
    for (const target of targets) {
      if (!graph.has(target)) {
        graph.set(target, []);
      }
    }
  }

  const color = new Map<string, 0 | 1 | 2>();
  const stack: string[] = [];

  const visit = (node: string): string[] | null => {
    const state = color.get(node) ?? 0;
    if (state === 1) {
      const start = stack.indexOf(node);
      return [...stack.slice(start), node];
    }
    if (state === 2) {
      return null;
    }

    color.set(node, 1);
    stack.push(node);
    for (const next of graph.get(node) ?? []) {
      const cycle = visit(next);
      if (cycle) {
        return cycle;
      }
    }
    stack.pop();
    color.set(node, 2);
    return null;
  };

  for (const node of [...graph.keys()].sort()) {
    const cycle = visit(node);
    if (cycle) {
      throw new McoError(
        "mco_invalid",
        `MCO delegation cycle: ${cycle.join(" -> ")}`,
      );
    }
  }
}

function meshEdges(offers: McoOffer[]): McoMeshEdge[] {
  const edges: McoMeshEdge[] = [];
  for (const offer of offers) {
    for (const call of offer.calls) {
      for (const toServiceId of call.delegatesTo) {
        edges.push({
          fromServiceId: offer.serviceId,
          callId: call.id,
          toServiceId,
          permission: call.permission,
        });
      }
    }
  }

  edges.sort((left, right) => edgeKey(left).localeCompare(edgeKey(right)));
  return edges;
}

function edgeKey(edge: McoMeshEdge): string {
  return `${edge.fromServiceId}\u0000${edge.callId}\u0000${edge.toServiceId}`;
}

function isMcoMethod(method: string): method is McoMethod {
  return (MCO_METHODS as readonly string[]).includes(method);
}

function deny(
  code: AuthorizationFailureCode,
  reason: string,
  details?: Record<string, unknown>,
): VerificationOutcome {
  return details
    ? { ok: false, code, reason, details }
    : { ok: false, code, reason };
}
