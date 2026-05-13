import type { MutationAuthorizationDraft } from "@athome/protocol";
import { createExternalMutationSigner, createAtHomeClient } from "@athome/sdk";

const apiBaseUrl =
  process.env["ATHOME_API_BASE_URL"] ?? "http://127.0.0.1:3000";
const identityId = process.env["ATHOME_IDENTITY_ID"] ?? "krav@home";
const currentRootKeyId = process.env["ATHOME_ROOT_KEY_ID"] ?? "root";
const signerUrl =
  process.env["ATHOME_EXTERNAL_SIGNER_URL"] ??
  "http://127.0.0.1:8787/sign-mutation";

async function signWithCurrentRoot(
  draft: MutationAuthorizationDraft,
): Promise<string> {
  const response = await fetch(signerUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      identityId,
      keyId: currentRootKeyId,
      draft,
      purpose: "root-rotation",
    }),
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
  const client = createAtHomeClient(apiBaseUrl);
  const signer = createExternalMutationSigner({
    identityId,
    keyId: currentRootKeyId,
    signDraft: signWithCurrentRoot,
  });

  const rotation = await client.rotateRootKey(identityId, signer);

  if ("privateKey" in rotation) {
    throw new Error("Root rotation response unexpectedly exported private key");
  }

  console.log(
    JSON.stringify(
      {
        identity: identityId,
        oldRootKeyId: rotation.rotated.oldRootKeyId,
        newRootKeyId: rotation.rotated.newRootKeyId,
        privateKeyExported: rotation.custody.privateKeyExported,
        nextStep:
          "Provision signing for newRootKeyId in external custody before issuing additional mutations.",
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
