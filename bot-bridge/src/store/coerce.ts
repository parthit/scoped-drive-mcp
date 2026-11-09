export function asDate(value: unknown): Date {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value;
  if (typeof value === "string" || typeof value === "number") {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date;
  }
  throw new Error("Expected a timestamp");
}

export function asDateOrNull(value: unknown): Date | null {
  if (value == null) return null;
  return asDate(value);
}

export function asMeta(value: unknown): Record<string, unknown> {
  if (typeof value === "string") {
    const parsed = JSON.parse(value) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    return {};
  }
  if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  return {};
}

export function isUniqueViolation(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = "code" in error ? String((error as { code: unknown }).code) : "";
  if (code === "23505") return true;
  const message = "message" in error ? String((error as { message: unknown }).message) : "";
  return /duplicate key|unique constraint/i.test(message);
}
