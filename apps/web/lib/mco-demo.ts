export const MCO_DEMO_ACTORS = {
  foreman: "foreman@krav",
  trustMeBro: "trust me bro",
} as const;

export const mcoDemoServices = [
  {
    serviceId: "inbox",
    calls: [
      {
        id: "draft-message",
        method: "POST",
        path: "/inbox/messages",
        permission: "email:draft",
        delegatesTo: ["pay"],
      },
    ],
  },
  {
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
  },
  {
    serviceId: "vault",
    calls: [
      {
        id: "delete-vault",
        method: "DELETE",
        path: "/vault",
        permission: "vault:delete",
        delegatesTo: [],
      },
    ],
  },
] as const;

export const mcoDemoServiceIds = mcoDemoServices.map(
  (service) => service.serviceId,
);
