# Suggestions

Ordered by what changes the product if you do it next. Items lower down are real and should wait.

## Do these before any new surface

1. **Give the person the key, or stop minting it.** Accept a client-generated public key on `POST /identities`, and store only that public key. If development mode still mints a key, return it once and do not write `privateKey: ""`. Add the regression test described in the quality review: default `buildApp()`, create, reopen the store, read the record.

2. **Make revocation possible after a restart.** The same change fixes safety. A name that cannot be revoked should not be issued.

3. **Make `npm run demo` run.** Call `runDemo()` from the script entry without depending on `import.meta.main`. Print the allow, deny, audience, and revocation outcomes. This is the smallest honest demo of the library.

4. **Show lookup failures as failures.** When `resolveNamespace` throws or the response is not OK, render an error. Do not fall through to `getNamespaceState` and a badge that says available. Do the same for ops rows that are fixtures: keep the label, and hide action buttons on fixture rows.

5. **Stop sending the root private key to a server action.** Sign `X-Home-Authorization` in the browser with WebCrypto. The server action in `apps/web/lib/mutation-actions.ts` should not accept `privateKey`.

## Do these before a public listener

6. **Upgrade Next.js and Fastify off the advisory ranges `npm audit` reported**, then re-run the API tests and the web build. Leave Vitest UI off on shared machines until tinypool and Vitest are past the critical advisories.

7. **Put a durable limiter in front of bootstrap**, or do not expose bootstrap. The in-memory limiter allowed 10 creates and rejected 990 of 1,000 in a single burst. Document that number on the ops page so it is not a surprise.

8. **Publish one witness public key** that outlives the process, or stop issuing witness receipts until you can. Receipts signed by a key that dies with the process are not evidence.

9. **Add a bound to dangerous permissions.** `payment:send`, `vault:delete`, and `social:post` should carry a constraint the verifier reads: a max amount, a target, or a confirmation id. A bare string is enough today.

## Leave these alone for now

10. **Do not build the D1 adapter or a global Postgres cluster next.** One thousand people onboarded on this machine in 24.8 seconds on SQLite and 36.3 seconds on JSON, into 14.7 MB and 8.6 MB. Capacity is not the constraint.

11. **Do not add more pricing tiers, ops pages, or webhook dashboards.** The Personal, Developer, and Infrastructure buttons do not complete a signup. Shipping another screen widens the gap the quality review measured.

12. **Keep both storage backends tested, and pick SQLite as the default for `npm run dev`.** JSON is a fine fixture format. It is a weaker default for a registry that also writes private records.

## Suggested sequence

One vertical slice, then stop and show it to someone else:

- Client-generated root key.
- `POST /identities` stores the public key.
- Register one agent.
- Allow one inbox draft.
- Deny one vault delete.
- Revoke the token.
- Restart the process and show that revoke still holds.
- The homepage resolves that name from the API, or shows an error.

That slice is smaller than v0.4 and larger than anything the website can do today.
