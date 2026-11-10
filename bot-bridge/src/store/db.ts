export interface Db {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>;
  transaction<T>(fn: (db: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}
