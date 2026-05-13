# npm Audit Notes for v0.3 Alpha

Date checked: 2026-05-13

Command:

```bash
npm audit --audit-level=moderate
```

Current result: fails with 12 advisories, including 7 moderate and 5 high findings. The direct remediation offered by npm requires `npm audit fix --force` and breaking dependency upgrades, so this is recorded as accepted risk for documentation/release-truth purposes only. Do not treat this file as approval to ship a production deployment without dependency remediation.

## Advisories

| Package path                                                         | Severity | Advisory                                                                                                                                                                  | Current exposure                                                                                                                                                    | npm suggested fix                                                           |
| -------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `vitest -> vite / vite-node / @vitest/mocker -> vite / esbuild`      | Moderate | GHSA-4w7w-66w2-5vf9: Vite optimized-deps source-map path traversal; GHSA-67mh-4wv8-2f99: esbuild development server request exposure                                      | Local development/test tooling. Risk applies when a vulnerable dev server is reachable by untrusted websites or untrusted paths can reach Vite dev assets.          | `npm audit fix --force`, upgrading to `vitest@4.1.6` as a breaking change.  |
| `fastify -> @fastify/ajv-compiler / fast-json-stringify -> fast-uri` | High     | GHSA-q3j6-qgpj-74h6 and GHSA-v39h-62p7-jpjc: percent-encoded path traversal / host confusion parsing issues                                                               | API runtime dependency path. Treat as release-blocking for production exposure until Fastify and transitive parser dependencies are upgraded and regression-tested. | `npm audit fix --force`, upgrading to `fastify@5.8.5` as a breaking change. |
| `fastify`                                                            | High     | GHSA-jx2c-rxcm-jvmq: content-type tab validation bypass; GHSA-444r-cwp2-x5xf: spoofable forwarded protocol/host; GHSA-mrq3-vjjr-p77c: sendWebStream memory allocation DoS | API runtime dependency path. Treat as release-blocking for production exposure until Fastify is upgraded and proxy/trust-boundary behavior is regression-tested.    | `npm audit fix --force`, upgrading to `fastify@5.8.5` as a breaking change. |
| `next -> postcss`                                                    | Moderate | GHSA-qx2v-qp2m-jg93: PostCSS CSS stringify XSS with unescaped `</style>`                                                                                                  | Web build dependency path. Risk depends on stringifying attacker-controlled CSS.                                                                                    | `npm audit fix --force`, with npm reporting a breaking Next.js change.      |

## Release Decision

For v0.3 alpha documentation cleanup, the risks are accepted only because this change does not alter dependency versions or runtime code. A production release should not accept the Fastify `fast-uri` path without a dependency upgrade and focused API regression pass.

## Required Follow-Up

- Upgrade or override the vulnerable Fastify direct and transitive dependency paths before any hosted production deployment.
- Re-check Vitest/Vite/esbuild after test-tool upgrades and confirm local dev servers are not exposed beyond localhost or untrusted networks.
- Re-check Next/PostCSS after web dependency upgrades and run the production web build.
- Replace this accepted-risk note with passing `npm audit --audit-level=moderate` output when remediation lands.
