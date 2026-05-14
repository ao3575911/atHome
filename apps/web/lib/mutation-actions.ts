"use server";

import { createMutationAuthorization } from "@athome/sdk";
import { getApiBaseUrl } from "./api-config";
import { maskSensitiveFields } from "./sensitive";

export type MutationOperation = "registerService" | "issueCapabilityToken";

export interface SignedMutationInput {
  identityId: string;
  privateKey: string;
  operation: MutationOperation;
  body: Record<string, unknown>;
}

export interface SignedMutationResult {
  ok: boolean;
  method: string;
  path: string;
  requestBody: Record<string, unknown>;
  authHeader: string;
  response: unknown;
  error?: string;
}

function serializeAuth(
  auth: ReturnType<typeof createMutationAuthorization>,
): string {
  return Buffer.from(JSON.stringify(auth), "utf8").toString("base64url");
}

function resolveOperationRoute(
  operation: MutationOperation,
  identityId: string,
): { path: string; method: string } {
  switch (operation) {
    case "registerService":
      return {
        path: `/identities/${encodeURIComponent(identityId)}/services`,
        method: "POST",
      };
    case "issueCapabilityToken":
      return {
        path: `/identities/${encodeURIComponent(identityId)}/capability-tokens`,
        method: "POST",
      };
  }
}

export async function sendSignedMutation(
  input: SignedMutationInput,
): Promise<SignedMutationResult> {
  const { identityId, privateKey, operation, body } = input;
  const baseUrl = getApiBaseUrl();
  const { path, method } = resolveOperationRoute(operation, identityId);

  let authHeader: string;
  try {
    const auth = createMutationAuthorization({
      issuer: identityId,
      signatureKeyId: "root",
      method,
      path,
      body,
      privateKey,
    });
    authHeader = serializeAuth(auth);
  } catch (error) {
    return {
      ok: false,
      method,
      path,
      requestBody: body,
      authHeader: "",
      response: null,
      error: `Signing failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  try {
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        "x-home-authorization": authHeader,
      },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const text = await response.text();
    const payload: unknown = text ? JSON.parse(text) : null;
    return {
      ok: response.ok,
      method,
      path,
      requestBody: body,
      authHeader,
      response: maskSensitiveFields(payload),
    };
  } catch (error) {
    return {
      ok: false,
      method,
      path,
      requestBody: body,
      authHeader,
      response: null,
      error: error instanceof Error ? error.message : "API request failed",
    };
  }
}
