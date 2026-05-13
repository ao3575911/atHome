import type { MutationAuthorizationDraft } from "@home/protocol";
import { createExternalMutationSigner, createHomeClient } from "@home/sdk";

export interface BrowserExternalSignerOptions {
  apiBaseUrl: string;
  identityId: string;
  rootKeyId: string;
  signerEndpoint: string;
}

async function requestBrowserSignature(
  endpoint: string,
  identityId: string,
  keyId: string,
  draft: MutationAuthorizationDraft,
): Promise<string> {
  const response = await fetch(endpoint, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identityId, keyId, draft }),
  });

  if (!response.ok) {
    throw new Error(`Browser signer failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as { signature?: unknown };
  if (typeof payload.signature !== "string" || payload.signature.length === 0) {
    throw new Error("Browser signer response did not include a signature");
  }

  return payload.signature;
}

export async function registerBrowserExternalSignerService(
  options: BrowserExternalSignerOptions,
): Promise<void> {
  const client = createHomeClient(options.apiBaseUrl);
  const signer = createExternalMutationSigner({
    identityId: options.identityId,
    keyId: options.rootKeyId,
    signDraft: (draft) =>
      requestBrowserSignature(
        options.signerEndpoint,
        options.identityId,
        options.rootKeyId,
        draft,
      ),
  });

  await client.addService(
    options.identityId,
    {
      id: "browser-external-signer",
      type: "agent",
      endpoint: `${window.location.origin}/agent`,
    },
    signer,
  );
}
