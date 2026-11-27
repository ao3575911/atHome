"use server";

import {
  authorizeMcoCall,
  generateEd25519KeyPair,
  signCanonicalPayload,
  type McoOffer,
  type McoOfferDraft,
} from "@ao3575911/protocol";
import { mcoDemoServices } from "@/lib/mco-demo";

const DEMO_ISSUED_AT = "2026-11-28T00:00:00.000Z";
const DEMO_EXPIRES_AT = "2027-11-28T00:00:00.000Z";
const demoKeys = generateEd25519KeyPair();

export type McoConsoleDecision = {
  ok: boolean;
  code: string | null;
  reason: string;
  actor: string;
  serviceId: string;
  method: string;
  path: string;
  permission: string;
  delegateServiceId: string | null;
};

export async function askMcoMesh(input: {
  actor: string;
  serviceId: string;
  delegateServiceId: string | null;
}): Promise<McoConsoleDecision> {
  const actor = input.actor.trim().slice(0, 80);
  const service = mcoDemoServices.find(
    (entry) => entry.serviceId === input.serviceId,
  );
  const call = service?.calls[0];
  if (!service || !call) {
    return {
      ok: false,
      code: "mco_call_not_offered",
      reason: "That service has no offer on this mesh.",
      actor,
      serviceId: input.serviceId,
      method: "",
      path: "",
      permission: "",
      delegateServiceId: input.delegateServiceId,
    };
  }

  const decision = authorizeMcoCall({
    offer: signDemoOffer(service.serviceId),
    method: call.method,
    path: call.path,
    permission: call.permission,
    delegateServiceId: input.delegateServiceId ?? undefined,
    now: DEMO_ISSUED_AT,
  });

  return {
    ok: decision.ok,
    code: decision.code ?? null,
    reason: decision.reason ?? "The call is on the offer.",
    actor,
    serviceId: service.serviceId,
    method: call.method,
    path: call.path,
    permission: call.permission,
    delegateServiceId: input.delegateServiceId,
  };
}

function signDemoOffer(serviceId: string): McoOffer {
  const service = mcoDemoServices.find(
    (entry) => entry.serviceId === serviceId,
  );
  if (!service) {
    throw new Error(`Unknown demo service: ${serviceId}`);
  }

  const draft: McoOfferDraft = {
    version: "mco-offer/v1",
    id: `${service.serviceId}#${DEMO_ISSUED_AT}`,
    issuer: "demo@atHome",
    serviceId: service.serviceId,
    calls: service.calls.map((call) => ({
      id: call.id,
      method: call.method,
      path: call.path,
      permission: call.permission,
      delegatesTo: [...call.delegatesTo],
    })),
    issuedAt: DEMO_ISSUED_AT,
    expiresAt: DEMO_EXPIRES_AT,
    signatureKeyId: "demo-root",
  };

  return {
    ...draft,
    signature: signCanonicalPayload(draft, demoKeys.privateKey),
  };
}
