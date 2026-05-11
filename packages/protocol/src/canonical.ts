function normalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeValue(item));
  }

  if (value && typeof value === "object" && !(value instanceof Date)) {
    const source = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};

    for (const key of Object.keys(source).sort()) {
      const entry = source[key];
      if (entry !== undefined) {
        result[key] = normalizeValue(entry);
      }
    }

    return result;
  }

  return value;
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(normalizeValue(value));
}
