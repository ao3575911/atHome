import { randomNonce } from "@home/protocol";
import { createExternalMutationSigner, createHomeClient } from "@home/sdk";

const apiBaseUrl =
  process.env["ATHOME_API_BASE_URL"] ?? "http://127.0.0.1:3000";
const identityId = process.env["ATHOME_IDENTITY_ID"] ?? "krav@home";
const rootKeyId = process.env["ATHOME_ROOT_KEY_ID"] ?? "root";
const signerUrl =
  process.env["ATHOME_EXTERNAL_SIGNER_URL"] ??
  "http://127.0.0.1:8787/sign-mutation";

async function signWithExternalCustody(draft: unknown): Promise<string> {
  const response = await fetch(signerUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identityId, keyId: rootKeyId, draft }),
  });

  if (!response.ok) {
    throw new Error(`External signer failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as { signature?: unknown };
  if (typeof payload.signature !== "string" || payload.signature.length === 0) {
    throw new Error("External signer response did not include a signature");
  }

  return payload.signature;
}

async function main(): Promise<void> {
  const client = createHomeClient(apiBaseUrl);
  const rootSigner = createExternalMutationSigner({
    identityId,
    keyId: rootKeyId,
    signDraft: signWithExternalCustody,
  });

  await client.addService(
    identityId,
    {
      id: "agent@krav",
      type: "agent",
      endpoint: "https://demo.local/agent",
    },
    rootSigner,
  );

  const agent = await client.addAgent(
    identityId,
    {
      id: "foreman@krav",
      allowedCapabilities: ["profile:read", "email:draft", "logs:analyze"],
      deniedCapabilities: ["payment:send", "vault:delete", "social:post"],
      endpoint: "https://demo.local/foreman",
      auditLogEndpoint: "https://demo.local/audit",
    },
    rootSigner,
  );

  const token = await client.issueCapabilityToken(
    identityId,
    {
      subject: "foreman@krav",
      permissions: ["profile:read", "email:draft"],
      denied: ["payment:send"],
      audience: "agent@krav",
      ttlSeconds: 3600,
      nonce: randomNonce(),
    },
    rootSigner,
  );

  const capabilityCheck = await client.verifyCapability(
    token.token,
    "email:draft",
    "agent@krav",
  );
  const resolved = await client.resolve("agent@krav");

  console.log(
    JSON.stringify(
      {
        identity: identityId,
        agent: agent.agent.id,
        agentPrivateKeyExported: agent.custody.privateKeyExported,
        resolved,
        capabilityCheck,
      },
      null,
      2,
    ),
  );
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
