import type {
  AuthorizationFailureCode,
  Permission,
  VerificationOutcome,
} from "./types.js";

type RequestRoutePermission = {
  method: string;
  pattern: RegExp;
  permission: Permission;
};

const REQUEST_PERMISSION_MAP: RequestRoutePermission[] = [
  {
    method: "GET",
    pattern: /^\/(?:public\/)?profile$/u,
    permission: "profile:read",
  },
  { method: "POST", pattern: /^\/emails\/draft$/u, permission: "email:draft" },
  {
    method: "POST",
    pattern: /^\/inbox\/messages$/u,
    permission: "email:draft",
  },
  { method: "POST", pattern: /^\/logs\/analyze$/u, permission: "logs:analyze" },
  {
    method: "POST",
    pattern: /^\/payments\/send$/u,
    permission: "payment:send",
  },
  { method: "DELETE", pattern: /^\/vault$/u, permission: "vault:delete" },
  { method: "POST", pattern: /^\/social\/posts$/u, permission: "social:post" },
];

export function resolvePermissionForRequest(
  method: string,
  path: string,
): Permission {
  const normalizedMethod = method.toUpperCase();
  const normalizedPath = path.split("?")[0] ?? path;
  const rule = REQUEST_PERMISSION_MAP.find(
    (entry) =>
      entry.method === normalizedMethod && entry.pattern.test(normalizedPath),
  );

  if (rule) {
    return rule.permission;
  }

  return `custom:${normalizedMethod.toLowerCase()}:${normalizedPath.replaceAll("/", ":").replace(/^:/u, "")}`;
}

export function canPerform(input: {
  requestedPermission: Permission;
  tokenPermissions: Permission[];
  tokenDenied?: Permission[] | undefined;
  agentAllowed: Permission[];
  agentDenied?: Permission[] | undefined;
  audience?: string | undefined;
  expectedAudience?: string | undefined;
  agentStatus?: "active" | "revoked" | "suspended" | undefined;
  tokenExpiresAt?: string | undefined;
  tokenRevoked?: boolean | undefined;
  tokenSignatureKeyStatus?: "active" | "deprecated" | "revoked" | undefined;
  now?: Date | undefined;
}): VerificationOutcome {
  const now = input.now ?? new Date();

  if (input.agentStatus === "revoked") {
    return {
      ok: false,
      code: "agent_revoked",
      reason: "Agent has been revoked",
    };
  }

  if (input.agentStatus === "suspended") {
    return { ok: false, code: "agent_suspended", reason: "Agent is suspended" };
  }

  if (input.tokenRevoked) {
    return {
      ok: false,
      code: "token_revoked",
      reason: "Capability token has been revoked",
    };
  }

  if (input.tokenSignatureKeyStatus === "revoked") {
    return {
      ok: false,
      code: "key_revoked",
      reason: "Token signing key has been revoked",
    };
  }

  if (input.expectedAudience) {
    if (!input.audience) {
      return {
        ok: false,
        code: "audience_required",
        reason: "Capability token audience is required",
      };
    }

    if (input.audience !== input.expectedAudience) {
      return {
        ok: false,
        code: "audience_mismatch",
        reason: "Capability token audience does not match verifier audience",
      };
    }
  }

  if (
    input.tokenExpiresAt &&
    Date.parse(input.tokenExpiresAt) <= now.getTime()
  ) {
    return {
      ok: false,
      code: "token_expired",
      reason: "Capability token has expired",
    };
  }

  if (input.tokenDenied?.includes(input.requestedPermission)) {
    return {
      ok: false,
      code: "permission_denied",
      reason: `Requested permission ${input.requestedPermission} is explicitly denied by token`,
    };
  }

  if (input.agentDenied?.includes(input.requestedPermission)) {
    return {
      ok: false,
      code: "permission_denied",
      reason: `Requested permission ${input.requestedPermission} is explicitly denied for the agent`,
    };
  }

  if (!input.tokenPermissions.includes(input.requestedPermission)) {
    return {
      ok: false,
      code: "permission_not_granted",
      reason: `Requested permission ${input.requestedPermission} is not granted`,
    };
  }

  if (!input.agentAllowed.includes(input.requestedPermission)) {
    return {
      ok: false,
      code: "permission_not_granted",
      reason: `Requested permission ${input.requestedPermission} is not granted to the agent`,
    };
  }

  return { ok: true };
}
