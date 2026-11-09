export type Err = {
  ok: false;
  error: string;
  message: string;
  details?: Record<string, unknown>;
};

export type Ok<T> = { ok: true; data: T };

export type Result<T> = Ok<T> | Err;

export function ok<T>(data: T): Ok<T> {
  return { ok: true, data };
}

export function err(error: string, message: string, details?: Record<string, unknown>): Err {
  if (details && Object.keys(details).length > 0) return { ok: false, error, message, details };
  return { ok: false, error, message };
}
