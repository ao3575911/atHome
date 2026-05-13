const DEFAULT_LOCAL_API_BASE_URL = "http://localhost:3000";

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/u, "");
}

export function getApiBaseUrl(): string {
  const configured =
    typeof window === "undefined"
      ? (process.env.ATHOME_API_BASE_URL ??
        process.env.HOME_API_BASE_URL ??
        process.env.NEXT_PUBLIC_ATHOME_API_BASE_URL ??
        process.env.NEXT_PUBLIC_HOME_API_BASE_URL)
      : (process.env.NEXT_PUBLIC_ATHOME_API_BASE_URL ??
        process.env.NEXT_PUBLIC_HOME_API_BASE_URL);

  return trimTrailingSlash(configured ?? DEFAULT_LOCAL_API_BASE_URL);
}
