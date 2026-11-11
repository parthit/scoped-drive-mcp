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

CREATE TABLE IF NOT EXISTS login_identities (
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users (user_id),
  label TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (provider, provider_user_id)
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

CREATE TABLE IF NOT EXISTS bot_settings_tokens (
  bot_id TEXT PRIMARY KEY REFERENCES bots (bot_id),
  token TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS notifiers (
  notifier_id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL REFERENCES bots (bot_id),
  kind TEXT NOT NULL,
  enabled BOOLEAN NOT NULL,
  url TEXT,
  auth_scheme TEXT NOT NULL,
  secret_ciphertext TEXT,
  secret_nonce TEXT,
  secret_hint TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  consecutive_auth_failures INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  CONSTRAINT notifiers_kind_check CHECK (kind IN ('webhook')),
  CONSTRAINT notifiers_scheme_check CHECK (
    auth_scheme IN ('bearer', 'bearer_and_x_automation_key', 'hmac_sha256', 'bearer_and_hmac')
  ),
  CONSTRAINT notifiers_bot_kind_unique UNIQUE (bot_id, kind)
);

CREATE TABLE IF NOT EXISTS notifier_deliveries (
  delivery_id TEXT PRIMARY KEY,
  msg_id TEXT NOT NULL UNIQUE REFERENCES messages (msg_id) ON DELETE CASCADE,
  notifier_id TEXT NOT NULL REFERENCES notifiers (notifier_id) ON DELETE CASCADE,
  to_bot TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  next_attempt_at TIMESTAMPTZ NOT NULL,
  last_status_code INTEGER,
  last_error TEXT,
  delivered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT notifier_deliveries_status_check CHECK (status IN ('pending', 'succeeded', 'dead'))
);

CREATE INDEX IF NOT EXISTS notifier_deliveries_due_idx
  ON notifier_deliveries (next_attempt_at)
  WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS rate_locks (
  actor TEXT PRIMARY KEY,
  window_start TIMESTAMPTZ NOT NULL,
  hits INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS connections (
  connection_id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL REFERENCES bots (bot_id),
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  credential_ciphertext TEXT,
  external_account_label TEXT,
  scope TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT connections_status_check CHECK (status IN ('active', 'disconnected')),
  CONSTRAINT connections_bot_provider UNIQUE (bot_id, provider)
);

CREATE TABLE IF NOT EXISTS connection_capabilities (
  connection_id TEXT NOT NULL REFERENCES connections (connection_id) ON DELETE CASCADE,
  capability_id TEXT NOT NULL,
  PRIMARY KEY (connection_id, capability_id)
);

CREATE TABLE IF NOT EXISTS resource_grants (
  grant_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES connections (connection_id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  external_id TEXT NOT NULL,
  name TEXT NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT resource_grants_kind_check CHECK (kind IN ('file', 'folder')),
  CONSTRAINT resource_grants_unique UNIQUE (connection_id, external_id)
);

CREATE TABLE IF NOT EXISTS access_requests (
  request_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES connections (connection_id) ON DELETE CASCADE,
  external_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  status TEXT NOT NULL,
  approval_token TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL,
  decided_at TIMESTAMPTZ,
  CONSTRAINT access_requests_status_check CHECK (status IN ('pending', 'approved', 'denied')),
  CONSTRAINT access_requests_kind_check CHECK (kind IN ('file', 'folder'))
);

CREATE UNIQUE INDEX IF NOT EXISTS access_requests_one_pending
  ON access_requests (connection_id, external_id)
  WHERE status = 'pending';
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
