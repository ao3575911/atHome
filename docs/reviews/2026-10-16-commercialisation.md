# Commercialisation

16 October 2026. Recommendation: do not sell atHome yet. Continue the protocol only along the slice that makes one paying design partner possible. A larger company, a hosted registry, or the prices already printed on the site would commercialize a demo that cannot finish signup.

## What would be for sale

The thing a buyer can use today is a TypeScript library that creates signed identities, issues audience-scoped tokens, and verifies requests. The population run shows that library can onboard 1,000 households on one laptop in under 40 seconds. That is a developer tool.

The thing the website offers for sale is a namespace platform:

| Tier on `/pricing` | Printed price | What the button does            | What the API does                                                                                                                    |
| ------------------ | ------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Personal           | $0            | Renders "Choose Personal"       | Development create returns a manifest and no key. Production create returns 403.                                                     |
| Developer          | $29           | Renders "Choose Developer"      | No API key is issued. Webhooks and usage analytics on the developer pages are not backed by the registry.                            |
| Infrastructure     | Custom        | Renders "Choose Infrastructure" | No SSO, no enterprise custody, no audit export a customer can turn on. Postgres exists as an adapter and is not the running default. |

Taking money for those tiers would sell a signup that cannot attach an agent and cannot revoke one.

## Who the buyer is, if the slice gets finished

The buyer is not a consumer comparing the pricing page with a social network. The buyer is a developer who already has an agent that calls someone else's service and needs that call to be attributable and revocable.

A plausible first sale, after the product can do it:

- A design partner runs the registry for their own agents.
- They verify requests in their service, in a separate process, using the public manifest.
- They pay for a hosted witness and revocation log, or for support of the library, once they depend on it weekly.

Until a partner is checking signatures in their own code, there is no evidence of willingness to pay. This review did not find usage, waitlists, or contracts in the repository. Do not treat the $29 figure as validated. It is copy.

## Why a bigger company is the wrong move

"Bigger" in the roadmap sense means a D1 adapter, global Postgres, replication lag, and more ops screens. The simulation says the engine is not the scarce resource:

- 1,000 persons, full policy lifecycle, SQLite: 24.8 seconds, 14.7 MB.
- The same population through the HTTP bootstrap limiter: 10 admitted, 990 rejected.
- Production admissions: zero.

A company built on that roadmap would hire for a distributed system in front of a door that is locked. The cost to serve the thousand-person case on one node is a small VM. Unit economics are not the problem. The missing product is the problem.

Starting a different project would drop the only asset that took real work: the verifier, the token rules, and the tests around them. The website can be rebuilt. The policy checks are what a new repo would spend months re-deriving.

## A commercial sequence that matches the evidence

1. **No charge.** Fix client-held keys, the demo script, and the false "available" state. Publish the library as the product.
2. **One design partner, still no self-serve checkout.** They integrate verify on one route. Success is their service rejecting a revoked token without asking atHome's server on the hot path, except for a revocation fetch they can cache.
3. **First paid offer, after that integration is real.** A hosted revocation and witness log for teams who do not want to run SQLite, plus a support contract. Price it from their alternative (an engineer running the log), not from the current $29 card.
4. **Leave Personal at zero and unimplemented** until a person can claim a name, attach an agent, and revoke it after a restart. Then the $0 tier is a true free tier instead of a broken button.

## Risks of commercializing early

- Charging for Developer while `POST /identities` returns 403 in production is a refund and a trust problem.
- The playground moving root keys through a Next.js server action is a custody claim the security review rejects. A customer who believes "keys stay in the browser" would be misled.
- Fixture ops data in a paid "Infrastructure" tier would mean a customer making abuse decisions on rows the registry did not write.
- Names are first-come. Selling a namespace before recovery works sells something the buyer cannot reclaim if the key is lost. The current API loses the key by default.

## Decision

Continue atHome as a protocol with one finished loop. Do not incorporate a go-to-market around the current site. Revisit a price only after one outside service depends on verification. The scale numbers say you can support that partner on a single SQLite file. You do not need a bigger platform to find out whether anyone wants this.
