# atHome API Cheat Sheet

Copy-paste guide for running the local API, registering an identity, registering services/agents, issuing capability tokens, and verifying signed requests.

> Scope: local developer/MVP flow. Production disables bootstrap identity creation and demo private-key export.

## 0. Requirements

```bash
npm install
jq --version
```

If `jq` is missing, install it or manually copy values from the JSON responses.

## 1. Start the API

Open terminal 1:

```bash
cd ~/Desktop/atHome/atHome/atHome
ATHOME_DEMO_PRIVATE_KEY_EXPORT=true npm run dev
```

The API listens on:

```text
http://127.0.0.1:3000
```

Useful browser/API links:

```text
Swagger UI:   http://127.0.0.1:3000/docs
OpenAPI JSON: http://127.0.0.1:3000/openapi.json
Health:       http://127.0.0.1:3000/health
```

## 2. Set shell variables

Open terminal 2:

```bash
cd ~/Desktop/atHome/atHome/atHome
export API='http://127.0.0.1:3000'
export IDENTITY='krav@atHome'
export SERVICE_ID='agent@krav'
export AGENT_ID='foreman@krav'
```

## 3. Helper: create signed mutation authorization headers

All mutating routes after identity bootstrap require `X-Home-Authorization`.

This helper signs the exact HTTP method, path, and body with the root private key.

```bash
home_auth() {
  METHOD="$1" PATH_VALUE="$2" BODY_VALUE="${3:-}" npx tsx -e '
    import { createMutationAuthorization, serializeMutationAuthorization } from "@athome/protocol";

    const bodyText = process.env.BODY_VALUE ?? "";
    const body = bodyText.length > 0 ? JSON.parse(bodyText) : undefined;
    const auth = createMutationAuthorization({
      issuer: process.env.IDENTITY!,
      signatureKeyId: process.env.ROOT_KEY_ID ?? "root",
      method: process.env.METHOD!,
      path: process.env.PATH_VALUE!,
      body,
      privateKey: process.env.ROOT_PRIVATE_KEY!
    });

    process.stdout.write(serializeMutationAuthorization(auth));
  '
}
```

## 4. Health check

```bash
curl -s "$API/health" | jq
```

Expected:

```json
{
  "ok": true
}
```

## 5. Create/bootstrap a root identity

This is dev-only. It is blocked when `NODE_ENV=production`.

```bash
CREATE_RESPONSE=$(curl -s -X POST "$API/identities" \
  -H 'content-type: application/json' \
  -d "{\"id\":\"$IDENTITY\"}")

echo "$CREATE_RESPONSE" | jq
export ROOT_KEY_ID=$(echo "$CREATE_RESPONSE" | jq -r '.rootKeyId')
export ROOT_PRIVATE_KEY=$(echo "$CREATE_RESPONSE" | jq -r '.privateKey')
```

If the identity already exists, either choose a new `IDENTITY` or clear local demo data intentionally.

## 6. Get an identity manifest

```bash
curl -s "$API/identities/$IDENTITY" | jq
```

## 7. Register a service endpoint

```bash
SERVICE_BODY=$(jq -nc \
  --arg id "$SERVICE_ID" \
  '{id:$id,type:"agent",endpoint:"https://demo.local/agent",capabilities:["email:draft","profile:read"]}')

SERVICE_AUTH=$(home_auth POST "/identities/$IDENTITY/services" "$SERVICE_BODY")

curl -s -X POST "$API/identities/$IDENTITY/services" \
  -H 'content-type: application/json' \
  -H "x-home-authorization: $SERVICE_AUTH" \
  -d "$SERVICE_BODY" | jq
```

## 8. Register an agent

```bash
AGENT_BODY=$(jq -nc \
  --arg id "$AGENT_ID" \
  '{
    id:$id,
    allowedCapabilities:["profile:read","email:draft","logs:analyze"],
    deniedCapabilities:["payment:send","vault:delete","social:post"],
    endpoint:"https://demo.local/foreman",
    auditLogEndpoint:"https://demo.local/audit"
  }')

AGENT_AUTH=$(home_auth POST "/identities/$IDENTITY/agents" "$AGENT_BODY")

AGENT_RESPONSE=$(curl -s -X POST "$API/identities/$IDENTITY/agents" \
  -H 'content-type: application/json' \
  -H "x-home-authorization: $AGENT_AUTH" \
  -d "$AGENT_BODY")

echo "$AGENT_RESPONSE" | jq
export AGENT_PUBLIC_KEY_ID=$(echo "$AGENT_RESPONSE" | jq -r '.publicKeyId')
export AGENT_PRIVATE_KEY=$(echo "$AGENT_RESPONSE" | jq -r '.privateKey')
```

## 9. Resolve an identity, service, or agent name

Resolve root identity:

```bash
curl -s -X POST "$API/resolve" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$IDENTITY\"}" | jq
```

Resolve service/sub-identity:

```bash
curl -s -X POST "$API/resolve" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$SERVICE_ID\"}" | jq
```

## 10. Issue a capability token

```bash
TOKEN_BODY=$(jq -nc \
  --arg subject "$AGENT_ID" \
  --arg audience "$SERVICE_ID" \
  '{
    subject:$subject,
    permissions:["profile:read","email:draft"],
    denied:["payment:send"],
    audience:$audience,
    ttlSeconds:3600
  }')

TOKEN_AUTH=$(home_auth POST "/identities/$IDENTITY/capability-tokens" "$TOKEN_BODY")

TOKEN_RESPONSE=$(curl -s -X POST "$API/identities/$IDENTITY/capability-tokens" \
  -H 'content-type: application/json' \
  -H "x-home-authorization: $TOKEN_AUTH" \
  -d "$TOKEN_BODY")

echo "$TOKEN_RESPONSE" | jq
export TOKEN_ID=$(echo "$TOKEN_RESPONSE" | jq -r '.tokenId')
export TOKEN_JSON=$(echo "$TOKEN_RESPONSE" | jq -c '.token')
```

## 11. Verify a capability token

```bash
VERIFY_CAP_BODY=$(jq -nc \
  --argjson token "$TOKEN_JSON" \
  --arg audience "$SERVICE_ID" \
  '{token:$token,permission:"email:draft",expectedAudience:$audience}')

curl -s -X POST "$API/verify/capability" \
  -H 'content-type: application/json' \
  -d "$VERIFY_CAP_BODY" | jq
```

Expected successful result:

```json
{
  "ok": true,
  "verification": {
    "ok": true
  }
}
```

## 12. Create a signed agent request

This signs a service request using the agent private key.

```bash
REQUEST_JSON=$(BODY_VALUE='{"subject":"Hello from atHome","message":"Draft this email."}' npx tsx -e '
  import { createSignedRequest, randomNonce } from "@athome/protocol";

  const token = JSON.parse(process.env.TOKEN_JSON!);
  const body = JSON.parse(process.env.BODY_VALUE!);
  const request = createSignedRequest({
    actor: process.env.AGENT_ID!,
    issuer: process.env.IDENTITY!,
    signatureKeyId: process.env.AGENT_PUBLIC_KEY_ID!,
    capabilityToken: token,
    method: "POST",
    path: "/emails/draft",
    body,
    privateKey: process.env.AGENT_PRIVATE_KEY!,
    nonce: randomNonce()
  });

  process.stdout.write(JSON.stringify(request));
')

echo "$REQUEST_JSON" | jq
```

## 13. Verify a signed request

```bash
VERIFY_REQUEST_BODY=$(jq -nc \
  --argjson request "$REQUEST_JSON" \
  --arg audience "$SERVICE_ID" \
  '{
    request:$request,
    body:{subject:"Hello from atHome",message:"Draft this email."},
    expectedAudience:$audience
  }')

curl -s -X POST "$API/verify/request" \
  -H 'content-type: application/json' \
  -d "$VERIFY_REQUEST_BODY" | jq
```

Expected successful result:

```json
{
  "ok": true,
  "verification": {
    "ok": true
  }
}
```

## 14. Verify a denied request path

`POST /payments/send` maps to `payment:send`, which the token/agent deny list blocks.

```bash
DENIED_REQUEST_JSON=$(BODY_VALUE='{"amount":25,"currency":"USD"}' npx tsx -e '
  import { createSignedRequest, randomNonce } from "@athome/protocol";

  const token = JSON.parse(process.env.TOKEN_JSON!);
  const body = JSON.parse(process.env.BODY_VALUE!);
  const request = createSignedRequest({
    actor: process.env.AGENT_ID!,
    issuer: process.env.IDENTITY!,
    signatureKeyId: process.env.AGENT_PUBLIC_KEY_ID!,
    capabilityToken: token,
    method: "POST",
    path: "/payments/send",
    body,
    privateKey: process.env.AGENT_PRIVATE_KEY!,
    nonce: randomNonce()
  });

  process.stdout.write(JSON.stringify(request));
')

DENIED_VERIFY_BODY=$(jq -nc \
  --argjson request "$DENIED_REQUEST_JSON" \
  --arg audience "$SERVICE_ID" \
  '{request:$request,body:{amount:25,currency:"USD"},expectedAudience:$audience}')

curl -s -X POST "$API/verify/request" \
  -H 'content-type: application/json' \
  -d "$DENIED_VERIFY_BODY" | jq
```

Expected: `verification.ok` is `false` with a permission-related code.

## 15. Revoke a capability token

```bash
REVOKE_TOKEN_AUTH=$(home_auth POST "/identities/$IDENTITY/capability-tokens/$TOKEN_ID/revoke" "")

curl -s -X POST "$API/identities/$IDENTITY/capability-tokens/$TOKEN_ID/revoke" \
  -H "x-home-authorization: $REVOKE_TOKEN_AUTH" | jq
```

Now verify the original request again:

```bash
curl -s -X POST "$API/verify/request" \
  -H 'content-type: application/json' \
  -d "$VERIFY_REQUEST_BODY" | jq
```

Expected: `verification.ok` is `false` with `token_revoked`.

## 16. Revoke an agent

```bash
REVOKE_AGENT_AUTH=$(home_auth POST "/identities/$IDENTITY/agents/$AGENT_ID/revoke" "")

curl -s -X POST "$API/identities/$IDENTITY/agents/$AGENT_ID/revoke" \
  -H "x-home-authorization: $REVOKE_AGENT_AUTH" | jq
```

Expected: future request verification for that agent fails with `agent_revoked`.

## 17. Revoke a public key

```bash
REVOKE_KEY_AUTH=$(home_auth POST "/identities/$IDENTITY/keys/$AGENT_PUBLIC_KEY_ID/revoke" "")

curl -s -X POST "$API/identities/$IDENTITY/keys/$AGENT_PUBLIC_KEY_ID/revoke" \
  -H "x-home-authorization: $REVOKE_KEY_AUTH" | jq
```

Expected: future request verification using that key fails with `key_revoked`.

## 18. Generate SDK schema-name pinning

```bash
npm run generate:sdk
```

This updates:

```text
packages/sdk/src/openapi-schema-names.ts
```

## 19. Run the built-in demo and verification gates

```bash
npm run demo
npm run typecheck
npm test
```

## API route index

| Method | Path                                                | Purpose                         | Auth                             |
| ------ | --------------------------------------------------- | ------------------------------- | -------------------------------- |
| `GET`  | `/health`                                           | Health check                    | No                               |
| `GET`  | `/openapi.json`                                     | Generated OpenAPI document      | No                               |
| `GET`  | `/docs`                                             | Swagger UI                      | No                               |
| `POST` | `/identities`                                       | Bootstrap identity              | Dev only; disabled in production |
| `GET`  | `/identities/:id`                                   | Fetch manifest                  | No                               |
| `POST` | `/identities/:id/services`                          | Register service endpoint       | `X-Home-Authorization`           |
| `POST` | `/identities/:id/agents`                            | Register agent                  | `X-Home-Authorization`           |
| `POST` | `/identities/:id/capability-tokens`                 | Issue capability token          | `X-Home-Authorization`           |
| `POST` | `/identities/:id/agents/:agentId/revoke`            | Revoke agent                    | `X-Home-Authorization`           |
| `POST` | `/identities/:id/capability-tokens/:tokenId/revoke` | Revoke token                    | `X-Home-Authorization`           |
| `POST` | `/identities/:id/keys/:keyId/revoke`                | Revoke public key               | `X-Home-Authorization`           |
| `POST` | `/resolve`                                          | Resolve root/service/agent name | No                               |
| `POST` | `/verify/capability`                                | Verify capability token         | No                               |
| `POST` | `/verify/request`                                   | Verify signed agent request     | No                               |

## Permission map used by request verification

| HTTP request           | Required permission |
| ---------------------- | ------------------- |
| `GET /profile`         | `profile:read`      |
| `GET /public/profile`  | `profile:read`      |
| `POST /emails/draft`   | `email:draft`       |
| `POST /inbox/messages` | `email:draft`       |
| `POST /logs/analyze`   | `logs:analyze`      |
| `POST /payments/send`  | `payment:send`      |
| `DELETE /vault`        | `vault:delete`      |
| `POST /social/posts`   | `social:post`       |

Unknown routes derive a custom permission string in the form:

```text
custom:<method>:<path-with-slashes-as-colons>
```

Example: `POST /widgets/create` becomes `custom:post:widgets:create`.

## Production notes

- Do not enable `ATHOME_DEMO_PRIVATE_KEY_EXPORT` outside local demo/dev.
- `POST /identities` is bootstrap-only and blocked in production.
- Production custody should use WebAuthn/passkeys, client-side signing, KMS, or HSM boundaries.
- Revocation/transparency is currently local-first; see the production design docs for the distributed model.
