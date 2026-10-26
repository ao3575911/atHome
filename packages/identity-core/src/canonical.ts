function normalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(normalizeValue);
  }

  if (value && typeof value === "object" && !(value instanceof Date)) {
    const source = value as Record<string, unknown>;
    const normalized: Record<string, unknown> = Object.create(null);

    for (const key of Object.keys(source).sort()) {
      const entry = source[key];
      if (entry !== undefined) {
        normalized[key] = normalizeValue(entry);
      }
    }

    return normalized;
  }

  return value;
}

export function canonicalizeA1(value: unknown): string {
  return JSON.stringify(normalizeValue(value));
}
