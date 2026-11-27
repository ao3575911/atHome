import { describe, expect, it } from "vitest";
import {
  authorizeMcoCall,
  canonicalize,
  IdentityRegistry,
  McoError,
  MemoryRegistryBackend,
  signIdentityManifest,
  type IdentityManifest,
  type McoOffer,
  type PrivateKeyMaterial,
} from "../src/index.js";

const ISSUED_AT = "2026-11-28T00:00:00.000Z";

async function meshRegistry(): Promise<{
  registry: IdentityRegistry;
  rootKey: PrivateKeyMaterial;
}> {
  const registry = new IdentityRegistry(new MemoryRegistryBackend());
  const { rootKey } = await registry.createIdentity("krav@atHome");
  await registry.registerService("krav@atHome", {
    id: "inbox",
    type: "inbox",
    endpoint: "https://inbox.example/hook",
  });
  await registry.registerService("krav@atHome", {
    id: "pay",
    type: "pay",
    endpoint: "https://pay.example/hook",
  });
  await registry.registerService("krav@atHome", {
    id: "vault",
    type: "vault",
    endpoint: "https://vault.example/hook",
  });
  return { registry, rootKey };
}

function inboxCalls(delegatesTo: string[] = ["pay"]) {
  return [
    {
      id: "draft-message",
      method: "POST",
      path: "/inbox/messages",
      permission: "email:draft",
      delegatesTo,
    },
  ];
}

describe("mesh capability offers", () => {
  it("publishes a signed offer and projects delegation edges", async () => {
    const { registry } = await meshRegistry();
    const published = await registry.publishMcoOffer("krav@atHome", {
      serviceId: "inbox",
      calls: inboxCalls(),
      now: ISSUED_AT,
      ttlSeconds: 3600,
    });

    expect(published.offer.version).toBe("mco-offer/v1");
    expect(published.offer.signature.length).toBeGreaterThan(0);
    expect(published.manifest.signature).not.toBe("");

    const mesh = await registry.readMcoMesh("krav@atHome");
    expect(mesh.offers).toHaveLength(1);
    expect(mesh.edges).toEqual([
      {
        fromServiceId: "inbox",
        callId: "draft-message",
        toServiceId: "pay",
        permission: "email:draft",
      },
    ]);

    const events = await registry.listEvents("krav@atHome");
    expect(events.some((event) => event.type === "mco.published")).toBe(true);
  });

  it("allows an offered delegation and denies the trust me bro hop", async () => {
    const { registry } = await meshRegistry();
    await registry.publishMcoOffer("krav@atHome", {
      serviceId: "inbox",
      calls: inboxCalls(),
      now: ISSUED_AT,
    });
    const pay = await registry.publishMcoOffer("krav@atHome", {
      serviceId: "pay",
      calls: [
        {
          id: "send-payment",
          method: "POST",
          path: "/payments/send",
          permission: "payment:send",
          delegatesTo: [],
        },
      ],
      now: ISSUED_AT,
    });

    const mesh = await registry.readMcoMesh("krav@atHome");
    const inbox = mesh.offers.find((offer) => offer.serviceId === "inbox");
    expect(inbox).toBeDefined();

    expect(
      authorizeMcoCall({
        offer: inbox as McoOffer,
        method: "post",
        path: "/inbox/messages",
        permission: "email:draft",
        delegateServiceId: "pay",
        now: ISSUED_AT,
      }).ok,
    ).toBe(true);

    const denied = authorizeMcoCall({
      offer: pay.offer,
      method: "POST",
      path: "/payments/send",
      permission: "payment:send",
      delegateServiceId: "vault",
      now: ISSUED_AT,
    });
    expect(denied.ok).toBe(false);
    expect(denied.code).toBe("mco_delegation_not_offered");
  });

  it("authorizes each permission offered on one route", async () => {
    const { registry } = await meshRegistry();
    const published = await registry.publishMcoOffer("krav@atHome", {
      serviceId: "pay",
      calls: [
        {
          id: "aaa-send",
          method: "POST",
          path: "/payments/send",
          permission: "payment:send",
          delegatesTo: [],
        },
        {
          id: "zzz-refund",
          method: "POST",
          path: "/payments/send",
          permission: "payment:refund",
          delegatesTo: ["inbox"],
        },
      ],
      now: ISSUED_AT,
    });

    expect(published.offer.calls.map((call) => call.id)).toEqual([
      "aaa-send",
      "zzz-refund",
    ]);

    expect(
      authorizeMcoCall({
        offer: published.offer,
        method: "POST",
        path: "/payments/send",
        permission: "payment:refund",
        delegateServiceId: "inbox",
        now: ISSUED_AT,
      }).ok,
    ).toBe(true);

    expect(
      authorizeMcoCall({
        offer: published.offer,
        method: "POST",
        path: "/payments/send",
        permission: "payment:send",
        now: ISSUED_AT,
      }).ok,
    ).toBe(true);

    const wrongHop = authorizeMcoCall({
      offer: published.offer,
      method: "POST",
      path: "/payments/send",
      permission: "payment:refund",
      delegateServiceId: "vault",
      now: ISSUED_AT,
    });
    expect(wrongHop.code).toBe("mco_delegation_not_offered");
    expect(wrongHop.details).toMatchObject({ callId: "zzz-refund" });
  });

  it("allows a hop listed on a later call with the same permission", () => {
    const offer: McoOffer = {
      version: "mco-offer/v1",
      id: "pay#2026-11-28T00:00:00.000Z",
      issuer: "krav@atHome",
      serviceId: "pay",
      calls: [
        {
          id: "aaa-send",
          method: "POST",
          path: "/payments/send",
          permission: "payment:send",
          delegatesTo: [],
        },
        {
          id: "zzz-send",
          method: "POST",
          path: "/payments/send",
          permission: "payment:send",
          delegatesTo: ["inbox"],
        },
      ],
      issuedAt: ISSUED_AT,
      expiresAt: "2026-11-28T01:00:00.000Z",
      signatureKeyId: "root",
      signature: "unsigned",
    };

    expect(
      authorizeMcoCall({
        offer,
        method: "POST",
        path: "/payments/send",
        permission: "payment:send",
        delegateServiceId: "inbox",
        now: ISSUED_AT,
      }).ok,
    ).toBe(true);
  });

  it("rejects two calls with the same method, path, and permission", async () => {
    const { registry } = await meshRegistry();
    await expect(
      registry.publishMcoOffer("krav@atHome", {
        serviceId: "pay",
        calls: [
          {
            id: "send-a",
            method: "POST",
            path: "/payments/send",
            permission: "payment:send",
          },
          {
            id: "send-b",
            method: "POST",
            path: "/payments/send",
            permission: "payment:send",
            delegatesTo: ["inbox"],
          },
        ],
        now: ISSUED_AT,
      }),
    ).rejects.toThrow(/MCO duplicate call: POST \/payments\/send payment:send/);
  });

  it("rejects a delegation cycle and a self-delegation", async () => {
    const { registry } = await meshRegistry();
    await registry.publishMcoOffer("krav@atHome", {
      serviceId: "inbox",
      calls: inboxCalls(["pay"]),
      now: ISSUED_AT,
    });

    await expect(
      registry.publishMcoOffer("krav@atHome", {
        serviceId: "pay",
        calls: [
          {
            id: "send-payment",
            method: "POST",
            path: "/payments/send",
            permission: "payment:send",
            delegatesTo: ["inbox"],
          },
        ],
        now: ISSUED_AT,
      }),
    ).rejects.toThrow(/MCO delegation cycle: inbox -> pay -> inbox/);

    await expect(
      registry.publishMcoOffer("krav@atHome", {
        serviceId: "pay",
        calls: [
          {
            id: "send-payment",
            method: "POST",
            path: "/payments/send",
            permission: "payment:send",
            delegatesTo: ["pay"],
          },
        ],
        now: ISSUED_AT,
      }),
    ).rejects.toThrow(/cannot delegate to its own service/);
  });

  it("replaces an offer, then retires it", async () => {
    const { registry } = await meshRegistry();
    await registry.publishMcoOffer("krav@atHome", {
      serviceId: "inbox",
      calls: inboxCalls(),
      now: ISSUED_AT,
    });
    await registry.publishMcoOffer("krav@atHome", {
      serviceId: "inbox",
      calls: inboxCalls([]),
      now: "2026-11-28T01:00:00.000Z",
    });

    const mesh = await registry.readMcoMesh("krav@atHome");
    expect(mesh.offers).toHaveLength(1);
    expect(mesh.edges).toEqual([]);

    const retired = await registry.retireMcoOffer("krav@atHome", "inbox");
    expect(retired.claims.some((claim) => claim.type === "mco.offer")).toBe(
      false,
    );
    expect((await registry.readMcoMesh("krav@atHome")).offers).toEqual([]);
  });

  it("fails closed when a resigned manifest carries a tampered offer", async () => {
    const backend = new MemoryRegistryBackend();
    const registry = new IdentityRegistry(backend);
    const { rootKey } = await registry.createIdentity("krav@atHome");
    await registry.registerService("krav@atHome", {
      id: "inbox",
      type: "inbox",
      endpoint: "https://inbox.example/hook",
    });
    const published = await registry.publishMcoOffer("krav@atHome", {
      serviceId: "inbox",
      calls: inboxCalls([]),
      now: ISSUED_AT,
    });

    const tampered = structuredClone(published.manifest);
    const claim = tampered.claims.find((entry) => entry.type === "mco.offer");
    expect(claim).toBeDefined();
    const offer = JSON.parse(claim?.value ?? "{}") as McoOffer;
    const firstCall = offer.calls[0];
    expect(firstCall).toBeDefined();
    if (!firstCall || !claim) {
      throw new Error("missing offer call");
    }
    firstCall.permission = "vault:delete";
    claim.value = canonicalize(offer);

    await backend.writeManifest(resign(tampered, rootKey));

    await expect(registry.readMcoMesh("krav@atHome")).rejects.toBeInstanceOf(
      McoError,
    );
  });

  it("keeps the offer readable after root rotation", async () => {
    const { registry } = await meshRegistry();
    await registry.publishMcoOffer("krav@atHome", {
      serviceId: "vault",
      calls: [
        {
          id: "delete-vault",
          method: "DELETE",
          path: "/vault",
          permission: "vault:delete",
        },
      ],
      now: ISSUED_AT,
    });

    await registry.rotateRootKey("krav@atHome");
    const mesh = await registry.readMcoMesh("krav@atHome");
    expect(mesh.offers[0]?.serviceId).toBe("vault");

    const expired = authorizeMcoCall({
      offer: mesh.offers[0] as McoOffer,
      method: "DELETE",
      path: "/vault",
      permission: "vault:delete",
      now: "2099-01-01T00:00:00.000Z",
    });
    expect(expired.code).toBe("mco_offer_expired");
  });
});

function resign(
  manifest: IdentityManifest,
  rootKey: PrivateKeyMaterial,
): IdentityManifest {
  return signIdentityManifest(
    {
      id: manifest.id,
      version: manifest.version,
      publicKeys: manifest.publicKeys,
      services: manifest.services,
      agents: manifest.agents,
      claims: manifest.claims,
      recovery: manifest.recovery,
      updatedAt: manifest.updatedAt,
      expiresAt: manifest.expiresAt,
      signatureKeyId: rootKey.id,
    },
    rootKey,
  );
}
