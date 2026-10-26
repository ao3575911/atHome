import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  IdentityRegistry,
  LocalJsonStore,
  SQLiteRegistryBackend,
  canonicalize,
  hashBody,
} from "@ao3575911/protocol";

const out: Record<string, unknown> = {};
const t = () => performance.now();

async function setup(kind: string) {
  const backend =
    kind === "json"
      ? new LocalJsonStore(await mkdtemp(join(tmpdir(), "st-")))
      : new SQLiteRegistryBackend(":memory:");
  const r = new IdentityRegistry(backend as never);
  await r.createIdentity("krav@atHome");
  await r.registerAgent("krav@atHome", {
    id: "foreman@krav",
    allowedCapabilities: ["email:draft"],
    deniedCapabilities: ["payment:send"],
    endpoint: "https://example.test/f",
  });
  const token = await r.issueCapabilityToken("krav@atHome", {
    subject: "foreman@krav",
    permissions: ["email:draft"],
    ttlSeconds: 3600,
  });
  return { r, token };
}
const sign = (
  r: IdentityRegistry,
  token: any,
  body: unknown,
  path = "/emails/draft",
) =>
  r.signRequest("krav@atHome", {
    actor: "foreman@krav",
    issuer: "krav@atHome",
    capabilityToken: token,
    method: "POST",
    path,
    body,
  });

for (const kind of ["sqlite", "json"]) {
  const { r, token } = await setup(kind);
  const N = kind === "json" ? 500 : 2000;
  const body = { s: "hi" };
  let s = t();
  const reqs = [];
  for (let i = 0; i < N; i++) reqs.push(await sign(r, token, body));
  const signMs = t() - s;
  s = t();
  let ok = 0;
  for (const q of reqs)
    if ((await r.verifyRequest("krav@atHome", q, { body })).ok) ok++;
  const verMs = t() - s;
  const C = 500;
  const par = [];
  for (let i = 0; i < C; i++) par.push(await sign(r, token, body));
  s = t();
  const res = await Promise.all(
    par.map((q) =>
      r
        .verifyRequest("krav@atHome", q, { body })
        .catch((e) => ({ ok: false, err: String(e.code ?? e) })),
    ),
  );
  const parMs = t() - s;
  const dup = await sign(r, token, body);
  const race: any[] = await Promise.all(
    Array.from({ length: 50 }, () =>
      r
        .verifyRequest("krav@atHome", dup, { body })
        .catch((e) => ({ ok: false, err: String(e.code ?? e) })),
    ),
  );
  const repl: any = await (r as any).backend
    ?.readReplayState?.()
    .catch(() => null);
  out[kind] = {
    noncesStored: repl ? Object.keys(repl.nonces).length : "n/a",
    N,
    signPerSec: Math.round(N / (signMs / 1000)),
    verifyPerSec: Math.round(N / (verMs / 1000)),
    verifyOk: ok,
    concurrent: {
      C,
      ms: Math.round(parMs),
      ok: res.filter((x) => x.ok).length,
      errors: res.filter((x: any) => x.err).length,
    },
    replayRace50: {
      accepted: race.filter((x) => x.ok).length,
      errors: race.filter((x) => x.err).length,
    },
  };
}

const { r, token } = await setup("sqlite");
const fail: Record<string, unknown> = {};
const body = { s: "hi" };
const q = await sign(r, token, body);
fail.tamperedBody = (
  await r.verifyRequest("krav@atHome", q, { body: { s: "x" } })
).code;
fail.replay =
  (await r.verifyRequest("krav@atHome", q, { body }),
  (await r.verifyRequest("krav@atHome", q, { body })).code);
const q2 = await sign(r, token, body);
fail.tamperedSig = (
  await r.verifyRequest(
    "krav@atHome",
    { ...q2, signature: q2.signature.slice(0, -4) + "AAAA" },
    { body },
  )
).code;
const q3 = await sign(r, token, { amount: 1 }, "/payments/send");
fail.deniedPermission = (
  await r.verifyRequest("krav@atHome", q3, { body: { amount: 1 } })
).code;
const expired = await r.issueCapabilityToken("krav@atHome", {
  subject: "foreman@krav",
  permissions: ["email:draft"],
  ttlSeconds: 1,
  issuedAt: new Date(Date.now() - 10000),
});
fail.expiredToken = (
  await r.verifyRequest("krav@atHome", await sign(r, expired, body), { body })
).code;
const rv = await r.issueCapabilityToken("krav@atHome", {
  subject: "foreman@krav",
  permissions: ["email:draft"],
});
await r.revokeCapabilityToken("krav@atHome", rv.id as never);
fail.revokedToken = (
  await r.verifyRequest("krav@atHome", await sign(r, rv, body), { body })
).code;
fail.unknownIdentity = await r
  .verifyRequest("nobody@atHome", q2, { body })
  .then(
    (x) => x.code,
    (e) => "throws: " + e.message,
  );
out.failures = fail;

const large: Record<string, unknown> = {};
for (const mb of [1, 10, 50]) {
  const b = { blob: "x".repeat(mb * 1024 * 1024) };
  const s = t();
  const qq = await sign(r, token, b);
  const ok = (await r.verifyRequest("krav@atHome", qq, { body: b })).ok;
  large[`${mb}MB`] = { ok, ms: Math.round(t() - s) };
}
for (const depth of [1000, 5000, 20000]) {
  let o: any = {};
  const root = o;
  for (let i = 0; i < depth; i++) {
    o.c = {};
    o = o.c;
  }
  try {
    const s = t();
    hashBody(root);
    canonicalize(root);
    large[`depth${depth}`] = { ok: true, ms: Math.round(t() - s) };
  } catch (e: any) {
    large[`depth${depth}`] = {
      ok: false,
      error: e.constructor.name + ": " + e.message.slice(0, 60),
    };
  }
}
const wide: Record<string, number> = {};
for (let i = 0; i < 200000; i++) wide["k" + i] = i;
{
  const s = t();
  hashBody(wide);
  large.keys200k = { ok: true, ms: Math.round(t() - s) };
}
out.largeInputs = large;
console.log(JSON.stringify(out, null, 2));
