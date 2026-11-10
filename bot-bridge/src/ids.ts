import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const INVITE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const left = createHash("sha256").update(a).digest();
  const right = createHash("sha256").update(b).digest();
  return timingSafeEqual(left, right);
}

export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString("base64url")}`;
}

export function randomToken(prefix: string, bytes = 32): string {
  return `${prefix}${randomBytes(bytes).toString("base64url")}`;
}

export function inviteCode(length = 10): string {
  const bytes = randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += INVITE_ALPHABET[bytes[i]! % INVITE_ALPHABET.length];
  }
  return out;
}

export function encodeCursor(createdAt: Date, msgId: string): string {
  return Buffer.from(`${createdAt.toISOString()}|${msgId}`, "utf8").toString("base64url");
}

export function decodeCursor(cursor: string): { createdAt: Date; msgId: string } | null {
  try {
    const raw = Buffer.from(cursor, "base64url").toString("utf8");
    const splitAt = raw.indexOf("|");
    if (splitAt <= 0) return null;
    const createdAt = new Date(raw.slice(0, splitAt));
    const msgId = raw.slice(splitAt + 1);
    if (Number.isNaN(createdAt.getTime()) || msgId.length === 0) return null;
    return { createdAt, msgId };
  } catch {
    return null;
  }
}

const TOKEN_SHAPE = /^[A-Za-z0-9_-]{1,80}$/;

export function isTokenShape(value: string): boolean {
  return TOKEN_SHAPE.test(value);
}
