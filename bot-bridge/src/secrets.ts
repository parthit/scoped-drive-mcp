import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export function encryptSecret(plaintext: string, kek: Buffer): { ciphertext: string; nonce: string } {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", kek, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([encrypted, tag]).toString("base64"),
    nonce: nonce.toString("base64"),
  };
}

export function decryptSecret(ciphertext: string, nonce: string, kek: Buffer): string {
  const nonceBuf = Buffer.from(nonce, "base64");
  const packed = Buffer.from(ciphertext, "base64");
  if (packed.length < 17) throw new Error("ciphertext_short");
  const tag = packed.subarray(packed.length - 16);
  const data = packed.subarray(0, packed.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", kek, nonceBuf);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

export function secretHint(secret: string): string {
  return secret.slice(-4);
}
