# npm Audit Notes for v0.3 Alpha

Date checked: 2026-05-13

Command:

```bash
npm audit --audit-level=moderate
```

Current result: fails with 7 moderate advisories and 0 high findings. The direct remediation offered by npm requires `npm audit fix --force` and breaking dependency upgrades, so this is recorded as accepted risk for documentation/release-truth purposes only. Do not treat this file as approval to ship a production deployment without dependency remediation.

## Advisories

| Package path                                                    | Severity | Advisory                                                                 | Current exposure                                                                                              | npm suggested fix                                                          |
| --------------------------------------------------------------- | -------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `vitest -> vite / vite-node / @vitest/mocker -> vite / esbuild` | Moderate | GHSA-67mh-4wv8-2f99: esbuild development server request exposure         | Local development/test tooling. Risk applies when a vulnerable dev server is reachable by untrusted websites. | `npm audit fix --force`, upgrading to `vitest@4.1.6` as a breaking change. |
| `next -> postcss`                                               | Moderate | GHSA-qx2v-qp2m-jg93: PostCSS CSS stringify XSS with unescaped `</style>` | Web build dependency path. Risk depends on stringifying attacker-controlled CSS.                              | `npm audit fix --force`, with npm reporting a breaking Next.js change.     |

## Release Decision

For v0.3 alpha documentation cleanup, the remaining moderate risks are accepted only because this change does not alter dependency versions or runtime code. A production release should still prioritize dependency remediation and regression testing before stable tagging.

## Required Follow-Up

- Re-check Vitest/Vite/esbuild after test-tool upgrades and confirm local dev servers are not exposed beyond localhost or untrusted networks.
- Re-check Next/PostCSS after web dependency upgrades and run the production web build.
- Replace this accepted-risk note with passing `npm audit --audit-level=moderate` output when remediation lands.
