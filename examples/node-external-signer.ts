import type { MutationAuthorizationDraft } from "@home/protocol";
import { createExternalMutationSigner, createHomeClient } from "@home/sdk";

const apiBaseUrl =
  process.env["ATHOME_API_BASE_URL"] ?? "http://127.0.0.1:3000";
const identityId = process.env["ATHOME_IDENTITY_ID"] ?? "krav@home";
const rootKeyId = process.env["ATHOME_ROOT_KEY_ID"] ?? "root";
const signerUrl =
  process.env["ATHOME_EXTERNAL_SIGNER_URL"] ??
  "http://127.0.0.1:8787/sign-mutation";

async function signMutationDraft(
  draft: MutationAuthorizationDraft,
): Promise<string> {
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
  const signer = createExternalMutationSigner({
    identityId,
    keyId: rootKeyId,
    signDraft: signMutationDraft,
  });

  const response = await client.addService(
    identityId,
    {
      id: "node-external-signer",
      type: "agent",
      endpoint: "https://example.test/node-external-signer",
    },
    signer,
  );

  console.log(
    JSON.stringify(
      {
        ok: response.ok,
        identity: response.manifest.id,
        signatureKeyId: response.manifest.signatureKeyId,
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
