export type AuthorizationFailureCode =
  | "permission_not_granted"
  | "permission_denied"
  | "audience_mismatch";

export interface CanPerformInput {
  requestedPermission: string;
  tokenPermissions: string[];
  tokenDenied?: string[] | undefined;
  agentAllowed: string[];
  agentDenied: string[];
  audience?: string | undefined;
  expectedAudience?: string | undefined;
}

export interface CanPerformResult {
  ok: boolean;
  code?: AuthorizationFailureCode;
  reason?: string;
}

function deny(
  code: AuthorizationFailureCode,
  reason: string,
): CanPerformResult {
  return { ok: false, code, reason };
}

export function canPerform(input: CanPerformInput): CanPerformResult {
  if (input.expectedAudience !== undefined) {
    if (input.audience !== input.expectedAudience) {
      return deny(
        "audience_mismatch",
        input.audience === undefined
          ? `Token does not declare required audience ${input.expectedAudience}`
          : `Token audience ${input.audience} does not match expected audience ${input.expectedAudience}`,
      );
    }
  }

  if (input.tokenDenied?.includes(input.requestedPermission)) {
    return deny(
      "permission_denied",
      `Requested permission ${input.requestedPermission} is explicitly denied by the capability token`,
    );
  }

  if (input.agentDenied.includes(input.requestedPermission)) {
    return deny(
      "permission_denied",
      `Requested permission ${input.requestedPermission} is explicitly denied for the agent`,
    );
  }

  if (!input.tokenPermissions.includes(input.requestedPermission)) {
    return deny(
      "permission_not_granted",
      `Requested permission ${input.requestedPermission} is not granted by the capability token`,
    );
  }

  if (!input.agentAllowed.includes(input.requestedPermission)) {
    return deny(
      "permission_not_granted",
      `Requested permission ${input.requestedPermission} is not allowed for the agent`,
    );
  }

  return { ok: true };
}
