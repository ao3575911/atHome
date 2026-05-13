export type ApiHealthResult =
  | {
      mode: "live";
      baseUrl: string;
      data: { ok: true };
    }
  | {
      mode: "unavailable";
      baseUrl: string;
      error: string;
    };

export type ApiResolveResult =
  | {
      mode: "live";
      baseUrl: string;
      data: unknown;
    }
  | {
      mode: "unavailable";
      baseUrl: string;
      error: string;
      demo: unknown;
    };

export function getApiBaseUrl(): string {
  return (
    process.env.ATHOME_API_BASE_URL ??
    process.env.NEXT_PUBLIC_ATHOME_API_BASE_URL ??
    "http://127.0.0.1:3000"
  ).replace(/\/$/u, "");
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return undefined;

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function fetchApiHealth(): Promise<ApiHealthResult> {
  const baseUrl = getApiBaseUrl();

  try {
    const response = await fetch(`${baseUrl}/health`, {
      cache: "no-store",
    });
    const data = await readJson(response);

    if (!response.ok || !data || typeof data !== "object") {
      return {
        mode: "unavailable",
        baseUrl,
        error: `Health check returned HTTP ${response.status}`,
      };
    }

    return {
      mode: "live",
      baseUrl,
      data: data as { ok: true },
    };
  } catch (error) {
    return {
      mode: "unavailable",
      baseUrl,
      error: errorMessage(error),
    };
  }
}

export async function resolveApiName(name: string): Promise<ApiResolveResult> {
  const baseUrl = getApiBaseUrl();
  const trimmed = name.trim() || "krav@atHome";

  try {
    const response = await fetch(`${baseUrl}/resolve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: trimmed }),
      cache: "no-store",
    });
    const data = await readJson(response);

    if (!response.ok) {
      return {
        mode: "unavailable",
        baseUrl,
        error: `Resolve returned HTTP ${response.status}`,
        demo: demoResolveResponse(trimmed),
      };
    }

    return {
      mode: "live",
      baseUrl,
      data,
    };
  } catch (error) {
    return {
      mode: "unavailable",
      baseUrl,
      error: errorMessage(error),
      demo: demoResolveResponse(trimmed),
    };
  }
}

function demoResolveResponse(name: string): unknown {
  return {
    ok: true,
    demo: true,
    name,
    resolvedType: name.includes("@") ? "root" : "service",
    rootIdentity: {
      id: name.includes("@") ? name : "krav@atHome",
      services: [
        {
          id: "agent@krav",
          type: "agent",
          endpoint: "https://demo.local/agent",
        },
      ],
    },
    manifestSignatureValid: true,
  };
}
