/**
 * Browser passkey signer demo.
 *
 * Demonstrates using a WebAuthn passkey credential to sign atHome mutation
 * authorization headers in the browser — no raw private key is ever exposed
 * to the SDK or the page.
 *
 * Prerequisites:
 *   - The user has a registered WebAuthn credential whose public key was
 *     provisioned into their atHome identity manifest.
 *   - The page is served over HTTPS (WebAuthn requirement).
 *   - `navigator.credentials` is available.
 */

import {
  createPasskeyMutationSigner,
  createAtHomeClient,
  type MutationAuthorization,
  type ServiceEndpoint,
} from "@athome/sdk";

export interface PasskeySignerOptions {
  apiBaseUrl: string;
  identityId: string;
  rootKeyId: string;
  credentialId: string;
}

/**
 * Calls `navigator.credentials.get` with the mutation draft as the WebAuthn
 * challenge and returns the raw assertion signature bytes.
 */
async function webAuthnAssertion(input: {
  identityId: string;
  keyId: string;
  challenge: Uint8Array;
}): Promise<{ signature: Uint8Array }> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: input.challenge.buffer as ArrayBuffer,
      rpId: window.location.hostname,
      userVerification: "required",
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("WebAuthn assertion cancelled or unavailable");
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  return { signature: new Uint8Array(response.signature) };
}

/**
 * Serializes a MutationAuthorization as a base64url-encoded JSON string,
 * matching the server's expected `X-Home-Authorization` header format.
 */
function serializeAuth(auth: MutationAuthorization): string {
  return btoa(JSON.stringify(auth))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Registers a service using a passkey-backed mutation signer.
 * The raw signing key never leaves the authenticator.
 */
export async function registerServiceWithPasskey(
  options: PasskeySignerOptions,
  service: ServiceEndpoint,
): Promise<void> {
  const client = createAtHomeClient(options.apiBaseUrl);

  const signer = createPasskeyMutationSigner({
    identityId: options.identityId,
    keyId: options.rootKeyId,
    credentialId: options.credentialId,
    requestAssertion: webAuthnAssertion,
  });

  await client.addService(options.identityId, service, signer);
}

/**
 * Registers a recovery method (e.g. a backup passkey credential) using the
 * primary passkey signer. Uses the raw fetch path since AtHomeClient does not
 * yet expose typed recovery-method helpers.
 */
export async function registerRecoveryMethodWithPasskey(
  options: PasskeySignerOptions,
  recoveryMethod: { id: string; type: "passkey" | "key"; value: string },
): Promise<void> {
  const signer = createPasskeyMutationSigner({
    identityId: options.identityId,
    keyId: options.rootKeyId,
    credentialId: options.credentialId,
    requestAssertion: webAuthnAssertion,
  });

  const path = `/identities/${encodeURIComponent(options.identityId)}/recovery-methods`;
  const auth = await signer.signMutation({
    method: "POST",
    path,
    body: recoveryMethod,
  });

  const res = await fetch(`${options.apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-home-authorization": serializeAuth(auth),
    },
    body: JSON.stringify(recoveryMethod),
  });

  if (!res.ok) {
    const err = (await res.json().catch(() => null)) as {
      error?: { message?: string };
    } | null;
    throw new Error(
      err?.error?.message ??
        `Recovery method registration failed: HTTP ${res.status}`,
    );
  }
}
