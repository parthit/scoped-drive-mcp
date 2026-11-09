import { PGlite } from "@electric-sql/pglite";
import type { Db } from "./db.js";

export class PgliteDb implements Db {
  constructor(private readonly pg: PGlite) {}

  async query<T>(sql: string, params: unknown[] = []): Promise<T[]> {
    const result = params.length === 0 ? await this.pg.query(sql) : await this.pg.query(sql, params);
    return result.rows as T[];
  }

  async transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    await this.pg.exec("BEGIN");
    const tx: Db = {
      query: (sql, params) => this.query(sql, params),
      transaction: (nested) => nested(tx),
      close: async () => undefined,
    };
    try {
      const value = await fn(tx);
      await this.pg.exec("COMMIT");
      return value;
    } catch (error) {
      await this.pg.exec("ROLLBACK");
      throw error;
    }
  }

  async close(): Promise<void> {
    await this.pg.close();
  }
}

export async function createPgliteDb(): Promise<PgliteDb> {
  const pg = new PGlite();
  return new PgliteDb(pg);
}
