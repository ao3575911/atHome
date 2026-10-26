// A short, readable walk through the protocol: one identity, one agent, one
// scoped token, and the checks a service runs before it acts.
// Run: npx tsx examples/tour.ts [--replay]
import { IdentityRegistry, SQLiteRegistryBackend } from "@athome/protocol";

const g = (s: string) => `\x1b[32m${s}\x1b[0m`;
const r = (s: string) => `\x1b[31m${s}\x1b[0m`;
const d = (s: string) => `\x1b[2m${s}\x1b[0m`;
const step = (s: string) => console.log(`\n\x1b[1m${s}\x1b[0m`);
const show = (label: string, o: { ok: boolean; code?: string | undefined }) =>
  console.log(
    `  ${label.padEnd(34)} ${o.ok ? g("accepted") : r(`rejected  ${o.code ?? ""}`)}`,
  );

const registry = new IdentityRegistry(new SQLiteRegistryBackend(":memory:"));
const id = "krav@atHome";
const body = { subject: "Hello", message: "Draft this email." };

step("1. Create a root identity");
const created = await registry.createIdentity(id);
console.log(
  `  ${id}  ${d(`root key ${created.manifest.publicKeys[0]!.publicKey.slice(12, 36)}…`)}`,
);

step("2. Register an agent with an allow and deny list");
await registry.registerAgent(id, {
  id: "foreman@krav",
  allowedCapabilities: ["email:draft"],
  deniedCapabilities: ["payment:send"],
  endpoint: "https://example.test/foreman",
});
console.log(
  `  foreman@krav  allow ${g("email:draft")}  deny ${r("payment:send")}`,
);

step("3. Issue a scoped capability token (1 hour)");
const token = await registry.issueCapabilityToken(id, {
  subject: "foreman@krav",
  permissions: ["email:draft"],
  ttlSeconds: 3600,
});
console.log(`  token ${token.id}  ${d(`expires ${token.expiresAt}`)}`);

const sign = (path: string, b: unknown) =>
  registry.signRequest(id, {
    actor: "foreman@krav",
    issuer: id,
    capabilityToken: token,
    method: "POST",
    path,
    body: b,
  });

if (process.argv.includes("--replay")) {
  step("4. Sign one request, then send it 25 times at once");
  const request = await sign("/emails/draft", body);
  const results = await Promise.all(
    Array.from({ length: 25 }, () =>
      registry.verifyRequest(id, request, { body }),
    ),
  );
  const ok = results.filter((x) => x.ok).length;
  console.log(
    `  ${g(`${ok} accepted`)}   ${r(`${results.length - ok} rejected  nonce_replayed`)}`,
  );
  step("5. Each signed request is good exactly once.");
} else {
  step("4. The service verifies each signed request");
  const good = await sign("/emails/draft", body);
  show("draft an email", await registry.verifyRequest(id, good, { body }));
  show(
    "same request again (replay)",
    await registry.verifyRequest(id, good, { body }),
  );
  const pay = await sign("/payments/send", { amount: 25 });
  show(
    "send a payment",
    await registry.verifyRequest(id, pay, { body: { amount: 25 } }),
  );
  const t = await sign("/emails/draft", body);
  show(
    "body changed in transit",
    await registry.verifyRequest(id, t, {
      body: { ...body, message: "Wire $5k" },
    }),
  );
  await registry.revokeCapabilityToken(id, token.id);
  const after = await sign("/emails/draft", body);
  show(
    "after the owner revokes the token",
    await registry.verifyRequest(id, after, { body }),
  );
  step("Authority stays local, signed, scoped and revocable.");
}
