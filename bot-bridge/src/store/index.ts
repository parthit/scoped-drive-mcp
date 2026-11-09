import { MemoryStore } from "./memory.js";
import { PgStore } from "./pg-store.js";
import { createPostgresDb } from "./postgres.js";
import type { Store } from "./types.js";

export async function createDefaultStore(): Promise<Store> {
  const url = process.env.DATABASE_URL?.trim();
  if (!url) {
    if (process.env.VERCEL) {
      throw new Error("DATABASE_URL is required on Vercel. Bot Bridge cannot pair or deliver mail without Postgres.");
    }
    console.warn("DATABASE_URL is not set. Using in-memory storage. Data disappears when this process stops.");
    return new MemoryStore();
  }
  const store = new PgStore(createPostgresDb(url));
  await store.ensureSchema();
  await store.ping();
  return store;
}

export { MemoryStore } from "./memory.js";
export { PgStore } from "./pg-store.js";
export type { Store } from "./types.js";
