const SENSITIVE_FIELD_PATTERN =
  /(^|_)(api[-_]?key|authorization|credential|private[-_]?key|secret|signature|token)(_|$)/iu;

function maskString(value: string): string {
  if (value.length <= 8) return "••••";
  return `${value.slice(0, 4)}••••${value.slice(-4)}`;
}

export function maskSensitiveFields(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => maskSensitiveFields(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [
        key,
        SENSITIVE_FIELD_PATTERN.test(key)
          ? typeof nestedValue === "string"
            ? maskString(nestedValue)
            : "••••"
          : maskSensitiveFields(nestedValue),
      ]),
    );
  }

  return value;
}

export function maskDisplayValue(value: string): string {
  return maskString(value);
}
