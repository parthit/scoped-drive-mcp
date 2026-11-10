import postgres from "postgres";
import type { Db } from "./db.js";

type Sql = postgres.Sql;

function sslMode(url: string): false | "require" {
  if (process.env.DATABASE_SSL === "disable") return false;
  try {
    const parsed = new URL(url);
    if (parsed.searchParams.get("sslmode") === "disable") return false;
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1") return false;
  } catch {
    return "require";
  }
  return "require";
}

class PostgresJsDb implements Db {
  constructor(private readonly sql: Sql) {}

  async query<T>(text: string, params: unknown[] = []): Promise<T[]> {
    const rows = params.length === 0 ? await this.sql.unsafe(text) : await this.sql.unsafe(text, params as never[]);
    return [...rows] as T[];
  }

  transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    return this.sql.begin(async (tx) => {
      const inner: Db = {
        query: async <R>(text: string, params: unknown[] = []) => {
          const rows = params.length === 0 ? await tx.unsafe(text) : await tx.unsafe(text, params as never[]);
          return [...rows] as R[];
        },
        transaction: (nested) => nested(inner),
        close: async () => undefined,
      };
      return fn(inner);
    }) as Promise<T>;
  }

  async close(): Promise<void> {
    await this.sql.end({ timeout: 5 });
  }
}

export function createPostgresDb(url: string): Db {
  const sql = postgres(url, {
    max: process.env.VERCEL ? 1 : 4,
    idle_timeout: 20,
    connect_timeout: 20,
    prepare: false,
    ssl: sslMode(url),
  });
  return new PostgresJsDb(sql);
}
