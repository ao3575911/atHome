import { getApiBaseUrl } from "./api-config";
import { maskSensitiveFields } from "./sensitive";

export type ApiConnectionSource = "api" | "fixture";

export type HealthEndpoint =
  | "/health"
  | "/health/live"
  | "/health/ready"
  | "/ready"
  | "/status";

export type AuditEvent = {
  id: string;
  type: string;
  identityId: string;
  subjectId: string;
  timestamp: string;
  signerKeyId: string;
  hash?: string;
};

export type AuditFetch = {
  source: ApiConnectionSource;
  events: AuditEvent[];
  error?: string;
};

export type HealthProbe = {
  endpoint: HealthEndpoint;
  ok: boolean;
  status: number | "offline";
  latencyMs: number | null;
  payload: unknown;
  error?: string;
};

export type ResolveResult = {
  ok: boolean;
  name: string;
  resolvedType: "root" | "service" | "agent" | "unknown";
  rootIdentity: { id?: string; type?: string } | null;
  resolvedEntry?: unknown;
  publicKey?: unknown;
  manifestSignatureValid: boolean;
};

export type ResolveLookup = {
  source: ApiConnectionSource;
  result: ResolveResult | null;
  error?: string;
};

const STATUS_ENDPOINTS: HealthEndpoint[] = [
  "/health/live",
  "/health/ready",
  "/status",
];

function endpointUrl(path: string): string {
  return `${getApiBaseUrl()}${path}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed";
}

async function readPayload(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export async function probeHealthEndpoint(
  endpoint: HealthEndpoint,
): Promise<HealthProbe> {
  const startedAt = Date.now();

  try {
    const response = await fetch(endpointUrl(endpoint), {
      cache: "no-store",
      headers: { accept: "application/json" },
    });
    const payload = await readPayload(response);

    return {
      endpoint,
      ok: response.ok,
      status: response.status,
      latencyMs: Date.now() - startedAt,
      payload: maskSensitiveFields(payload),
      ...(response.ok ? {} : { error: `HTTP ${response.status}` }),
    };
  } catch (error) {
    return {
      endpoint,
      ok: false,
      status: "offline",
      latencyMs: null,
      payload: null,
      error: errorMessage(error),
    };
  }
}

export async function getStatusProbes(): Promise<HealthProbe[]> {
  return Promise.all(
    STATUS_ENDPOINTS.map((endpoint) => probeHealthEndpoint(endpoint)),
  );
}

export async function fetchAuditEvents(): Promise<AuditFetch> {
  try {
    const response = await fetch(endpointUrl("/audit/events"), {
      cache: "no-store",
      headers: { accept: "application/json" },
    });
    const payload = await readPayload(response);

    if (!response.ok) {
      return {
        source: "fixture",
        events: [],
        error: `HTTP ${response.status}`,
      };
    }

    const data = payload as { ok: boolean; events?: AuditEvent[] };
    return {
      source: "api",
      events: (data.events ?? []).map(
        (event) => maskSensitiveFields(event) as AuditEvent,
      ),
    };
  } catch (error) {
    return { source: "fixture", events: [], error: errorMessage(error) };
  }
}

export type RegistryFreshness = {
  identityId: string;
  generatedAt: string;
  manifestUpdatedAt?: string;
  latestEventId?: string;
  latestEventTimestamp?: string;
  eventCount: number;
  witnessReceiptCount: number;
};

export type FreshnessFetch = {
  source: ApiConnectionSource;
  freshness: RegistryFreshness | null;
  error?: string;
};

export async function fetchRegistryFreshness(
  identityId: string,
): Promise<FreshnessFetch> {
  try {
    const response = await fetch(
      `${endpointUrl("/registry/freshness")}?identityId=${encodeURIComponent(identityId)}`,
      { cache: "no-store", headers: { accept: "application/json" } },
    );
    const payload = await readPayload(response);

    if (!response.ok) {
      return {
        source: "fixture",
        freshness: null,
        error: `HTTP ${response.status}`,
      };
    }

    const data = payload as { ok: boolean; freshness?: RegistryFreshness };
    return { source: "api", freshness: data.freshness ?? null };
  } catch (error) {
    return { source: "fixture", freshness: null, error: errorMessage(error) };
  }
}

export async function resolveNamespace(name: string): Promise<ResolveLookup> {
  try {
    const response = await fetch(endpointUrl("/resolve"), {
      method: "POST",
      cache: "no-store",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ name }),
    });
    const payload = await readPayload(response);

    if (!response.ok) {
      return {
        source: "fixture",
        result: null,
        error:
          payload && typeof payload === "object" && "error" in payload
            ? JSON.stringify(maskSensitiveFields(payload))
            : `HTTP ${response.status}`,
      };
    }

    const maskedPayload = maskSensitiveFields(payload) as ResolveResult;
    return {
      source: "api",
      result: {
        ...maskedPayload,
        name,
      },
    };
  } catch (error) {
    return {
      source: "fixture",
      result: null,
      error: errorMessage(error),
    };
  }
}
