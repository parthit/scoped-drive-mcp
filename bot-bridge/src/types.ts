export const LINK_STATUSES = ["awaiting_peer", "pending_approval", "active", "revoked"] as const;
export type LinkStatus = (typeof LINK_STATUSES)[number];
export type Side = "a" | "b";
export const SCOPE = "messages_only" as const;
export type Scope = typeof SCOPE;

export type UserRow = {
  user_id: string;
  email: string | null;
  created_at: Date;
};

export type IdentityRow = {
  provider: string;
  provider_user_id: string;
  user_id: string;
  label: string;
  created_at: Date;
};

export type ConnectionRow = {
  connection_id: string;
  bot_id: string;
  provider: string;
  status: "active" | "disconnected";
  credential_ciphertext: string | null;
  external_account_label: string | null;
  scope: string | null;
  created_at: Date;
};

export type GrantRow = {
  grant_id: string;
  connection_id: string;
  kind: "file" | "folder";
  external_id: string;
  name: string;
  granted_at: Date;
};

export type AccessRequestRow = {
  request_id: string;
  connection_id: string;
  external_id: string;
  kind: "file" | "folder";
  capability_id: string;
  status: "pending" | "approved" | "denied";
  approval_token: string;
  created_at: Date;
  decided_at: Date | null;
};

export type BotRow = {
  bot_id: string;
  user_id: string;
  display_name: string;
  token_hash: string;
  created_at: Date;
};

export type LinkRow = {
  link_id: string;
  bot_a: string;
  bot_b: string | null;
  scope: Scope;
  status: LinkStatus;
  invite_code: string;
  approved_a_at: Date | null;
  approved_b_at: Date | null;
  revoked_at: Date | null;
  revoked_by: string | null;
  created_at: Date;
};

export type ApprovalRow = {
  approval_id: string;
  link_id: string;
  user_id: string;
  side: Side;
  token: string;
  expires_at: Date;
  consumed_at: Date | null;
};

export type ManageRow = {
  link_id: string;
  bot_id: string;
  token: string;
  created_at: Date;
};

export type MessageRow = {
  msg_id: string;
  link_id: string;
  from_bot: string;
  to_bot: string;
  body: string;
  thread_id: string;
  idempotency_key: string | null;
  created_at: Date;
  read_at: Date | null;
  expires_at: Date;
};

export const AUTH_SCHEMES = ["bearer", "bearer_and_x_automation_key", "hmac_sha256", "bearer_and_hmac"] as const;
export type AuthScheme = (typeof AUTH_SCHEMES)[number];
export const NOTIFIER_KINDS = ["webhook"] as const;
export type NotifierKind = (typeof NOTIFIER_KINDS)[number];
export const DELIVERY_STATUSES = ["pending", "succeeded", "dead"] as const;
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number];

export type SettingsTokenRow = {
  bot_id: string;
  token: string;
  created_at: Date;
};

export type NotifierRow = {
  notifier_id: string;
  bot_id: string;
  kind: NotifierKind;
  enabled: boolean;
  url: string | null;
  auth_scheme: AuthScheme;
  secret_ciphertext: string | null;
  secret_nonce: string | null;
  secret_hint: string | null;
  created_at: Date;
  updated_at: Date;
  consecutive_auth_failures: number;
  last_error: string | null;
};

export type DeliveryRow = {
  delivery_id: string;
  msg_id: string;
  notifier_id: string;
  to_bot: string;
  status: DeliveryStatus;
  attempts: number;
  next_attempt_at: Date;
  last_status_code: number | null;
  last_error: string | null;
  delivered_at: Date | null;
  created_at: Date;
};

export type AuditRow = {
  event_id: string;
  actor: string;
  action: string;
  link_id: string | null;
  meta_json: Record<string, unknown>;
  created_at: Date;
};

export type InboxFilter = {
  toBot: string;
  now: Date;
  linkId?: string;
  unreadOnly?: boolean;
  since?: Date;
  before?: { createdAt: Date; msgId: string };
  limit: number;
};

export function deriveStatus(link: Pick<LinkRow, "revoked_at" | "bot_b" | "approved_a_at" | "approved_b_at">): LinkStatus {
  if (link.revoked_at) return "revoked";
  if (!link.bot_b) return "awaiting_peer";
  if (link.approved_a_at && link.approved_b_at) return "active";
  return "pending_approval";
}

export function sideOf(link: Pick<LinkRow, "bot_a" | "bot_b">, botId: string): Side | null {
  if (link.bot_a === botId) return "a";
  if (link.bot_b === botId) return "b";
  return null;
}

export function peerId(link: Pick<LinkRow, "bot_a" | "bot_b">, botId: string): string | null {
  const side = sideOf(link, botId);
  if (side === "a") return link.bot_b;
  if (side === "b") return link.bot_a;
  return null;
}
