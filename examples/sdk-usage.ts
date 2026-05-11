import {
  createSignedRequest,
  randomNonce,
  type SignedRequest,
} from "@home/protocol";
import { createHomeClient, createRootMutationSigner } from "@home/sdk";

async function main(): Promise<void> {
  const client = createHomeClient("http://127.0.0.1:3000");

  const identity = await client.createIdentity("krav@home");
  const rootSigner = createRootMutationSigner({
    identityId: "krav@home",
    keyId: identity.rootKeyId,
    privateKey: identity.privateKey!,
  });

  await client.addService(
    "krav@home",
    {
      id: "agent@krav",
      type: "agent",
      endpoint: "https://demo.local/agent",
    },
    rootSigner,
  );

  const agent = await client.addAgent(
    "krav@home",
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
    "krav@home",
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

  const request: SignedRequest = createSignedRequest({
    actor: "foreman@krav",
    issuer: "krav@home",
    capabilityToken: token.token,
    signatureKeyId: agent.publicKeyId,
    method: "POST",
    path: "/emails/draft",
    body: {
      subject: "Hello from the SDK example",
      message: "Draft this message for me.",
    },
    privateKey: agent.privateKey!,
    nonce: randomNonce(),
  });

  const capabilityCheck = await client.verifyCapability(
    token.token,
    "email:draft",
    "agent@krav",
  );
  const requestCheck = await client.verifyRequest(
    request,
    {
      subject: "Hello from the SDK example",
      message: "Draft this message for me.",
    },
    "agent@krav",
  );

  const resolved = await client.resolve("agent@krav");

  console.log(
    JSON.stringify(
      {
        identity: identity.manifest.id,
        agent: agent.agent.id,
        resolved,
        capabilityCheck,
        requestCheck,
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
