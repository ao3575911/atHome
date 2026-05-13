import {
  generateEd25519KeyPair,
  createSignedRequest,
  randomNonce,
  type SignedRequest,
} from "@athome/protocol";
import { createAtHomeClient, createInMemoryMutationSigner } from "@athome/sdk";

async function main(): Promise<void> {
  const client = createAtHomeClient("http://127.0.0.1:3000");
  const bootstrapKeys = generateEd25519KeyPair();
  const agentKeys = generateEd25519KeyPair();

  const rootSigner = createInMemoryMutationSigner({
    identityId: "krav@atHome",
    keyId: "root",
    privateKey: bootstrapKeys.privateKey,
  });

  const identity = await client.createIdentity("krav@atHome", rootSigner);

  await client.addService(
    "krav@atHome",
    {
      id: "agent@krav",
      type: "agent",
      endpoint: "https://demo.local/agent",
    },
    rootSigner,
  );

  const agent = await client.addAgent(
    "krav@atHome",
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
    "krav@atHome",
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
    issuer: "krav@atHome",
    capabilityToken: token.token,
    signatureKeyId: "foreman@krav#agent",
    method: "POST",
    path: "/emails/draft",
    body: {
      subject: "Hello from the SDK example",
      message: "Draft this message for me.",
    },
    privateKey: agentKeys.privateKey,
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
