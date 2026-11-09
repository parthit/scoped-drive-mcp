/**
 * Postgres schema for Bot Bridge.
 * Applied automatically on startup when DATABASE_URL is set.
 * Approval tokens and manage tokens are stored so the same human URL can be shown again.
 * Bot bearer tokens are stored only as SHA-256 hashes (see bots.token_hash).
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  email TEXT,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS bots (
  bot_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users (user_id),
  display_name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS links (
  link_id TEXT PRIMARY KEY,
  bot_a TEXT NOT NULL REFERENCES bots (bot_id),
  bot_b TEXT REFERENCES bots (bot_id),
  scope TEXT NOT NULL,
  status TEXT NOT NULL,
  invite_code TEXT NOT NULL UNIQUE,
  approved_a_at TIMESTAMPTZ,
  approved_b_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revoked_by TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT links_status_check CHECK (status IN ('awaiting_peer', 'pending_approval', 'active', 'revoked')),
  CONSTRAINT links_scope_check CHECK (scope = 'messages_only'),
  CONSTRAINT links_distinct_bots CHECK (bot_b IS NULL OR bot_a <> bot_b)
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL REFERENCES links (link_id),
  user_id TEXT NOT NULL REFERENCES users (user_id),
  side TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  CONSTRAINT approvals_side_check CHECK (side IN ('a', 'b'))
);

CREATE UNIQUE INDEX IF NOT EXISTS approvals_one_open_per_side
  ON approvals (link_id, side)
  WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS manage_tokens (
  link_id TEXT NOT NULL REFERENCES links (link_id),
  bot_id TEXT NOT NULL REFERENCES bots (bot_id),
  token TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (link_id, bot_id)
);

CREATE TABLE IF NOT EXISTS messages (
  msg_id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL REFERENCES links (link_id),
  from_bot TEXT NOT NULL REFERENCES bots (bot_id),
  to_bot TEXT NOT NULL REFERENCES bots (bot_id),
  body TEXT NOT NULL,
  thread_id TEXT NOT NULL,
  idempotency_key TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  read_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT messages_idempotency_unique UNIQUE (from_bot, idempotency_key)
);

CREATE INDEX IF NOT EXISTS messages_inbox_idx
  ON messages (to_bot, created_at DESC, msg_id DESC);

CREATE INDEX IF NOT EXISTS messages_expires_idx
  ON messages (expires_at);

CREATE INDEX IF NOT EXISTS messages_thread_idx
  ON messages (thread_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
  event_id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  link_id TEXT,
  meta_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_actor_idx
  ON audit_events (actor, created_at DESC);

CREATE TABLE IF NOT EXISTS rate_locks (
  actor TEXT PRIMARY KEY,
  window_start TIMESTAMPTZ NOT NULL,
  hits INTEGER NOT NULL
);
`;

export function schemaStatements(sql = SCHEMA_SQL): string[] {
  return sql
    .split(";")
    .map((part) =>
      part
        .split("\n")
        .filter((line) => !line.trim().startsWith("--"))
        .join("\n")
        .trim(),
    )
    .filter((part) => part.length > 0);
}
