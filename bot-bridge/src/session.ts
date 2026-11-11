import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type SessionPayload = {
  user_id: string;
  csrf: string;
  exp: number;
};

export function seal(secret: string, payload: Record<string, unknown>): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export function openSealed(secret: string, token: string, now: Date): Record<string, unknown> | null {
  const splitAt = token.lastIndexOf(".");
  if (splitAt <= 0) return null;
  const body = token.slice(0, splitAt);
  const sig = token.slice(splitAt + 1);
  const expected = createHmac("sha256", secret).update(body).digest("base64url");
  const left = Buffer.from(sig);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, unknown>;
    if (typeof parsed.exp !== "number" || parsed.exp <= now.getTime()) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function openSession(secret: string, token: string, now: Date): SessionPayload | null {
  const parsed = openSealed(secret, token, now);
  if (!parsed || typeof parsed.user_id !== "string" || typeof parsed.csrf !== "string") return null;
  return { user_id: parsed.user_id, csrf: parsed.csrf, exp: Number(parsed.exp) };
}

export function newCsrf(): string {
  return randomBytes(18).toString("base64url");
}
