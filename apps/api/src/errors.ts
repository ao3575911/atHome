import type { AuthorizationFailureCode } from "@home/protocol";

export type ApiErrorCode =
  | AuthorizationFailureCode
  | "invalid_request"
  | "not_found"
  | "identity_not_found"
  | "identity_already_exists"
  | "service_already_exists"
  | "agent_already_exists"
  | "missing_private_record"
  | "missing_root_key"
  | "missing_public_key"
  | "mutation_unauthorized"
  | "internal_error";

export interface ApiErrorEnvelope {
  ok: false;
  error: {
    code: ApiErrorCode;
    message: string;
    details: Record<string, unknown>;
  };
}

export class ApiError extends Error {
  constructor(
    public readonly code: ApiErrorCode,
    message: string,
    public readonly statusCode = 400,
    public readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function apiError(
  code: ApiErrorCode,
  message: string,
  statusCode = 400,
  details: Record<string, unknown> = {},
): ApiError {
  return new ApiError(code, message, statusCode, details);
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) {
    return error;
  }

  if (typeof error === "object" && error !== null) {
    const maybeFastifyError = error as {
      code?: string;
      statusCode?: number;
      validation?: unknown;
      message?: string;
    };

    if (
      maybeFastifyError.code === "FST_ERR_VALIDATION" ||
      maybeFastifyError.statusCode === 400 ||
      maybeFastifyError.validation !== undefined
    ) {
      return apiError(
        "invalid_request",
        maybeFastifyError.message ?? "Invalid request",
        400,
        {
          validation: maybeFastifyError.validation,
        },
      );
    }
  }

  if (error instanceof Error) {
    const message = error.message;

    if (message.startsWith("Identity already exists: ")) {
      return apiError("identity_already_exists", message, 409);
    }

    if (message.startsWith("Service already exists: ")) {
      return apiError("service_already_exists", message, 409);
    }

    if (message.startsWith("Agent already exists: ")) {
      return apiError("agent_already_exists", message, 409);
    }

    if (message.startsWith("Unknown identity: ")) {
      return apiError("identity_not_found", "Identity not found", 404);
    }

    if (message.startsWith("Missing private record for: ")) {
      return apiError(
        "missing_private_record",
        "Private identity record is unavailable",
        404,
      );
    }

    if (message.startsWith("Missing root key for: ")) {
      return apiError("missing_root_key", "Root key is unavailable", 500);
    }

    if (message.startsWith("Permission not allowed for agent: ")) {
      return apiError("permission_not_granted", message, 403, {
        permission: message.slice("Permission not allowed for agent: ".length),
      });
    }

    if (message.startsWith("Permission denied for agent: ")) {
      return apiError("permission_denied", message, 403, {
        permission: message.slice("Permission denied for agent: ".length),
      });
    }

    if (message.startsWith("Capability token cannot both allow and deny: ")) {
      return apiError("invalid_request", message, 400);
    }
  }

  return apiError("internal_error", "Internal server error", 500);
}

export function toErrorEnvelope(error: unknown): ApiErrorEnvelope {
  const apiErrorValue = toApiError(error);
  return {
    ok: false,
    error: {
      code: apiErrorValue.code,
      message: apiErrorValue.message,
      details: apiErrorValue.details,
    },
  };
}
