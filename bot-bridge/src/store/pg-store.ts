import { schemaStatements } from "../schema.js";
import type { ApprovalRow, AuditRow, BotRow, DeliveryRow, InboxFilter, LinkRow, ManageRow, MessageRow, NotifierKind, NotifierRow, SettingsTokenRow, Side, UserRow } from "../types.js";
import { asDate, asDateOrNull, asMeta } from "./coerce.js";
import type { Db } from "./db.js";
import type { Store } from "./types.js";

type Raw = Record<string, unknown>;

export class PgStore implements Store {
  readonly kind = "postgres" as const;

  constructor(private readonly db: Db) {}

  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => fn(new PgStore(tx)));
  }

  async ping(): Promise<void> {
    await this.db.query("SELECT 1 AS ok");
  }

  async ensureSchema(): Promise<void> {
    for (const statement of schemaStatements()) {
      await this.db.query(statement);
    }
  }

  async clearAll(): Promise<void> {
    await this.db.query(
      "TRUNCATE TABLE notifier_deliveries, notifiers, bot_settings_tokens, audit_events, messages, manage_tokens, approvals, links, bots, users, rate_locks RESTART IDENTITY CASCADE",
    );
  }

  async insertUser(row: UserRow): Promise<void> {
    await this.db.query("INSERT INTO users (user_id, email, created_at) VALUES ($1, $2, $3)", [
      row.user_id,
      row.email,
      row.created_at,
    ]);
  }

  async insertBot(row: BotRow): Promise<void> {
    await this.db.query(
      "INSERT INTO bots (bot_id, user_id, display_name, token_hash, created_at) VALUES ($1, $2, $3, $4, $5)",
      [row.bot_id, row.user_id, row.display_name, row.token_hash, row.created_at],
    );
  }

  async findBotByTokenHash(hash: string): Promise<BotRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM bots WHERE token_hash = $1", [hash]);
    return rows[0] ? mapBot(rows[0]) : null;
  }

  async findBotById(id: string): Promise<BotRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM bots WHERE bot_id = $1", [id]);
    return rows[0] ? mapBot(rows[0]) : null;
  }

  async lockBot(botId: string): Promise<void> {
    await this.db.query("SELECT bot_id FROM bots WHERE bot_id = $1 FOR UPDATE", [botId]);
  }

  async insertLink(row: LinkRow): Promise<"ok" | "conflict"> {
    const rows = await this.db.query<Raw>(
      `INSERT INTO links (
         link_id, bot_a, bot_b, scope, status, invite_code,
         approved_a_at, approved_b_at, revoked_at, revoked_by, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (invite_code) DO NOTHING
       RETURNING link_id`,
      [
        row.link_id,
        row.bot_a,
        row.bot_b,
        row.scope,
        row.status,
        row.invite_code,
        row.approved_a_at,
        row.approved_b_at,
        row.revoked_at,
        row.revoked_by,
        row.created_at,
      ],
    );
    return rows.length > 0 ? "ok" : "conflict";
  }

  async findLinkById(id: string): Promise<LinkRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM links WHERE link_id = $1", [id]);
    return rows[0] ? mapLink(rows[0]) : null;
  }

  async findLinkByInvite(code: string): Promise<LinkRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM links WHERE invite_code = $1", [code]);
    return rows[0] ? mapLink(rows[0]) : null;
  }

  async lockLink(id: string): Promise<LinkRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM links WHERE link_id = $1 FOR UPDATE", [id]);
    return rows[0] ? mapLink(rows[0]) : null;
  }

  async listLinksForBot(botId: string): Promise<LinkRow[]> {
    const rows = await this.db.query<Raw>(
      "SELECT * FROM links WHERE bot_a = $1 OR bot_b = $1 ORDER BY created_at DESC, link_id DESC",
      [botId],
    );
    return rows.map(mapLink);
  }

  async attachPeer(linkId: string, botId: string): Promise<LinkRow | null> {
    const rows = await this.db.query<Raw>(
      `UPDATE links SET
         bot_b = $2,
         status = CASE
           WHEN approved_a_at IS NOT NULL AND approved_b_at IS NOT NULL THEN 'active'
           ELSE 'pending_approval'
         END
       WHERE link_id = $1 AND bot_b IS NULL AND revoked_at IS NULL AND bot_a <> $2
       RETURNING *`,
      [linkId, botId],
    );
    return rows[0] ? mapLink(rows[0]) : null;
  }

  async markApproved(linkId: string, side: Side, at: Date): Promise<LinkRow | null> {
    const rows = await this.db.query<Raw>(
      `UPDATE links SET
         approved_a_at = CASE WHEN $2 = 'a' THEN COALESCE(approved_a_at, $3) ELSE approved_a_at END,
         approved_b_at = CASE WHEN $2 = 'b' THEN COALESCE(approved_b_at, $3) ELSE approved_b_at END,
         status = CASE
           WHEN revoked_at IS NOT NULL THEN 'revoked'
           WHEN bot_b IS NULL THEN 'awaiting_peer'
           WHEN (CASE WHEN $2 = 'a' THEN COALESCE(approved_a_at, $3) ELSE approved_a_at END) IS NOT NULL
            AND (CASE WHEN $2 = 'b' THEN COALESCE(approved_b_at, $3) ELSE approved_b_at END) IS NOT NULL
           THEN 'active'
           ELSE 'pending_approval'
         END
       WHERE link_id = $1 AND revoked_at IS NULL
       RETURNING *`,
      [linkId, side, at],
    );
    return rows[0] ? mapLink(rows[0]) : null;
  }

  async revoke(linkId: string, at: Date, by: string): Promise<LinkRow | null> {
    const rows = await this.db.query<Raw>(
      `UPDATE links SET
         revoked_at = COALESCE(revoked_at, $2),
         revoked_by = COALESCE(revoked_by, $3),
         status = 'revoked'
       WHERE link_id = $1
       RETURNING *`,
      [linkId, at, by],
    );
    return rows[0] ? mapLink(rows[0]) : null;
  }

  async insertApproval(row: ApprovalRow): Promise<"ok" | "conflict"> {
    const rows = await this.db.query<Raw>(
      `INSERT INTO approvals (approval_id, link_id, user_id, side, token, expires_at, consumed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (token) DO NOTHING
       RETURNING approval_id`,
      [row.approval_id, row.link_id, row.user_id, row.side, row.token, row.expires_at, row.consumed_at],
    );
    return rows.length > 0 ? "ok" : "conflict";
  }

  async findOpenApproval(linkId: string, side: Side): Promise<ApprovalRow | null> {
    const rows = await this.db.query<Raw>(
      `SELECT * FROM approvals
       WHERE link_id = $1 AND side = $2 AND consumed_at IS NULL
       ORDER BY expires_at DESC
       LIMIT 1`,
      [linkId, side],
    );
    return rows[0] ? mapApproval(rows[0]) : null;
  }

  async findApprovalByToken(token: string): Promise<ApprovalRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM approvals WHERE token = $1", [token]);
    return rows[0] ? mapApproval(rows[0]) : null;
  }

  async updateApproval(row: ApprovalRow): Promise<ApprovalRow | null> {
    const rows = await this.db.query<Raw>(
      `UPDATE approvals
       SET token = $2, expires_at = $3
       WHERE approval_id = $1 AND consumed_at IS NULL
       RETURNING *`,
      [row.approval_id, row.token, row.expires_at],
    );
    return rows[0] ? mapApproval(rows[0]) : null;
  }

  async consumeApproval(approvalId: string, at: Date): Promise<ApprovalRow | null> {
    const rows = await this.db.query<Raw>(
      `UPDATE approvals SET consumed_at = $2
       WHERE approval_id = $1 AND consumed_at IS NULL
       RETURNING *`,
      [approvalId, at],
    );
    return rows[0] ? mapApproval(rows[0]) : null;
  }

  async insertManageToken(row: ManageRow): Promise<"ok" | "exists"> {
    const rows = await this.db.query<Raw>(
      `INSERT INTO manage_tokens (link_id, bot_id, token, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (link_id, bot_id) DO NOTHING
       RETURNING token`,
      [row.link_id, row.bot_id, row.token, row.created_at],
    );
    return rows.length > 0 ? "ok" : "exists";
  }

  async findManageToken(linkId: string, botId: string): Promise<ManageRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM manage_tokens WHERE link_id = $1 AND bot_id = $2", [
      linkId,
      botId,
    ]);
    return rows[0] ? mapManage(rows[0]) : null;
  }

  async findManageByToken(token: string): Promise<ManageRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM manage_tokens WHERE token = $1", [token]);
    return rows[0] ? mapManage(rows[0]) : null;
  }

  async insertMessage(row: MessageRow): Promise<"ok" | "conflict"> {
    const values = [
      row.msg_id,
      row.link_id,
      row.from_bot,
      row.to_bot,
      row.body,
      row.thread_id,
      row.idempotency_key,
      row.created_at,
      row.read_at,
      row.expires_at,
    ];
    const insert = `INSERT INTO messages (
         msg_id, link_id, from_bot, to_bot, body, thread_id, idempotency_key, created_at, read_at, expires_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`;
    if (row.idempotency_key == null) {
      await this.db.query(insert, values);
      return "ok";
    }
    const rows = await this.db.query<Raw>(
      `${insert} ON CONFLICT (from_bot, idempotency_key) DO NOTHING RETURNING msg_id`,
      values,
    );
    return rows.length > 0 ? "ok" : "conflict";
  }

  async findMessageById(id: string): Promise<MessageRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM messages WHERE msg_id = $1", [id]);
    return rows[0] ? mapMessage(rows[0]) : null;
  }

  async findMessageByIdempotency(fromBot: string, key: string): Promise<MessageRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM messages WHERE from_bot = $1 AND idempotency_key = $2", [
      fromBot,
      key,
    ]);
    return rows[0] ? mapMessage(rows[0]) : null;
  }

  async listInbox(filter: InboxFilter): Promise<MessageRow[]> {
    const { sql, params } = inboxQuery(filter, false);
    const rows = await this.db.query<Raw>(sql, params);
    return rows.map(mapMessage);
  }

  async countInbox(filter: Omit<InboxFilter, "limit" | "before">): Promise<number> {
    const { sql, params } = inboxQuery({ ...filter, limit: 0 }, true);
    const rows = await this.db.query<{ count: number | string }>(sql, params);
    return Number(rows[0]?.count ?? 0);
  }

  async countSentSince(botId: string, since: Date, linkId?: string): Promise<number> {
    const params: unknown[] = [botId, since];
    let sql = "SELECT COUNT(*)::int AS count FROM messages WHERE from_bot = $1 AND created_at > $2";
    if (linkId) {
      params.push(linkId);
      sql += ` AND link_id = $${params.length}`;
    }
    const rows = await this.db.query<{ count: number | string }>(sql, params);
    return Number(rows[0]?.count ?? 0);
  }

  async oldestSentSince(botId: string, since: Date, linkId?: string): Promise<Date | null> {
    const params: unknown[] = [botId, since];
    let sql = "SELECT MIN(created_at) AS oldest FROM messages WHERE from_bot = $1 AND created_at > $2";
    if (linkId) {
      params.push(linkId);
      sql += ` AND link_id = $${params.length}`;
    }
    const rows = await this.db.query<{ oldest: unknown }>(sql, params);
    return rows[0]?.oldest == null ? null : asDate(rows[0].oldest);
  }

  async markMessagesRead(botId: string, ids: string[], now: Date): Promise<number> {
    let marked = 0;
    for (const id of ids) {
      const rows = await this.db.query(
        `UPDATE messages AS m SET read_at = $3
         WHERE m.msg_id = $1 AND m.to_bot = $2 AND m.read_at IS NULL AND m.expires_at > $3
           AND EXISTS (SELECT 1 FROM links l WHERE l.link_id = m.link_id AND l.status = 'active')
         RETURNING m.msg_id`,
        [id, botId, now],
      );
      marked += rows.length;
    }
    return marked;
  }

  async deleteMessagesForLink(linkId: string): Promise<number> {
    const rows = await this.db.query("DELETE FROM messages WHERE link_id = $1 RETURNING msg_id", [linkId]);
    return rows.length;
  }

  async deleteExpiredMessages(now: Date): Promise<number> {
    const rows = await this.db.query("DELETE FROM messages WHERE expires_at <= $1 RETURNING msg_id", [now]);
    return rows.length;
  }

  async threadLinkIds(threadId: string): Promise<string[]> {
    const rows = await this.db.query<{ link_id: string }>("SELECT DISTINCT link_id FROM messages WHERE thread_id = $1", [
      threadId,
    ]);
    return rows.map((row) => row.link_id);
  }

  async messagesInThreadForBot(threadId: string, botId: string, now: Date): Promise<MessageRow[]> {
    const rows = await this.db.query<Raw>(
      `SELECT * FROM messages
       WHERE thread_id = $1 AND expires_at > $2 AND (from_bot = $3 OR to_bot = $3)
       ORDER BY created_at DESC
       LIMIT 20`,
      [threadId, now, botId],
    );
    return rows.map(mapMessage);
  }

  async tryConsumeRate(actor: string, now: Date, windowMs: number, limit: number): Promise<boolean> {
    const cutoff = new Date(now.getTime() - windowMs);
    const rows = await this.db.query(
      `INSERT INTO rate_locks (actor, window_start, hits)
       VALUES ($1, $2, 1)
       ON CONFLICT (actor) DO UPDATE
       SET window_start = CASE
             WHEN rate_locks.window_start <= $3 THEN EXCLUDED.window_start
             ELSE rate_locks.window_start
           END,
           hits = CASE
             WHEN rate_locks.window_start <= $3 THEN 1
             ELSE rate_locks.hits + 1
           END
       WHERE rate_locks.window_start <= $3 OR rate_locks.hits < $4
       RETURNING hits`,
      [actor, now, cutoff, limit],
    );
    return rows.length > 0;
  }

  async insertSettingsToken(row: SettingsTokenRow): Promise<"ok" | "exists"> {
    const rows = await this.db.query(
      `INSERT INTO bot_settings_tokens (bot_id, token, created_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (bot_id) DO NOTHING
       RETURNING bot_id`,
      [row.bot_id, row.token, row.created_at],
    );
    return rows.length > 0 ? "ok" : "exists";
  }

  async findSettingsTokenByBot(botId: string): Promise<SettingsTokenRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM bot_settings_tokens WHERE bot_id = $1", [botId]);
    return rows[0] ? mapSettings(rows[0]) : null;
  }

  async findSettingsTokenByToken(token: string): Promise<SettingsTokenRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM bot_settings_tokens WHERE token = $1", [token]);
    return rows[0] ? mapSettings(rows[0]) : null;
  }

  async rotateSettingsToken(botId: string, token: string, at: Date): Promise<SettingsTokenRow | null> {
    const rows = await this.db.query<Raw>(
      `UPDATE bot_settings_tokens SET token = $2, created_at = $3 WHERE bot_id = $1 RETURNING *`,
      [botId, token, at],
    );
    return rows[0] ? mapSettings(rows[0]) : null;
  }

  async upsertNotifier(row: NotifierRow): Promise<NotifierRow> {
    const rows = await this.db.query<Raw>(
      `INSERT INTO notifiers (
         notifier_id, bot_id, kind, enabled, url, auth_scheme, secret_ciphertext, secret_nonce, secret_hint,
         created_at, updated_at, consecutive_auth_failures, last_error
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       ON CONFLICT (bot_id, kind) DO UPDATE SET
         enabled = EXCLUDED.enabled,
         url = EXCLUDED.url,
         auth_scheme = EXCLUDED.auth_scheme,
         secret_ciphertext = EXCLUDED.secret_ciphertext,
         secret_nonce = EXCLUDED.secret_nonce,
         secret_hint = EXCLUDED.secret_hint,
         updated_at = EXCLUDED.updated_at,
         consecutive_auth_failures = 0,
         last_error = NULL
       RETURNING *`,
      [
        row.notifier_id,
        row.bot_id,
        row.kind,
        row.enabled,
        row.url,
        row.auth_scheme,
        row.secret_ciphertext,
        row.secret_nonce,
        row.secret_hint,
        row.created_at,
        row.updated_at,
        row.consecutive_auth_failures,
        row.last_error,
      ],
    );
    return mapNotifier(rows[0]!);
  }

  async findNotifier(botId: string, kind: NotifierKind): Promise<NotifierRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM notifiers WHERE bot_id = $1 AND kind = $2", [botId, kind]);
    return rows[0] ? mapNotifier(rows[0]) : null;
  }

  async deleteNotifier(botId: string, kind: NotifierKind): Promise<boolean> {
    const rows = await this.db.query("DELETE FROM notifiers WHERE bot_id = $1 AND kind = $2 RETURNING notifier_id", [botId, kind]);
    return rows.length > 0;
  }

  async setNotifierHealth(
    notifierId: string,
    input: { enabled: boolean; consecutiveAuthFailures: number; lastError: string | null },
  ): Promise<void> {
    await this.db.query(
      `UPDATE notifiers SET enabled = $2, consecutive_auth_failures = $3, last_error = $4 WHERE notifier_id = $1`,
      [notifierId, input.enabled, input.consecutiveAuthFailures, input.lastError],
    );
  }

  async insertDelivery(row: DeliveryRow): Promise<"ok" | "conflict"> {
    const rows = await this.db.query(
      `INSERT INTO notifier_deliveries (
         delivery_id, msg_id, notifier_id, to_bot, status, attempts, next_attempt_at, last_status_code, last_error, delivered_at, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (msg_id) DO NOTHING
       RETURNING delivery_id`,
      [
        row.delivery_id,
        row.msg_id,
        row.notifier_id,
        row.to_bot,
        row.status,
        row.attempts,
        row.next_attempt_at,
        row.last_status_code,
        row.last_error,
        row.delivered_at,
        row.created_at,
      ],
    );
    return rows.length > 0 ? "ok" : "conflict";
  }

  async findDelivery(deliveryId: string): Promise<DeliveryRow | null> {
    const rows = await this.db.query<Raw>("SELECT * FROM notifier_deliveries WHERE delivery_id = $1", [deliveryId]);
    return rows[0] ? mapDelivery(rows[0]) : null;
  }

  async latestDelivery(botId: string): Promise<DeliveryRow | null> {
    const rows = await this.db.query<Raw>(
      `SELECT * FROM notifier_deliveries WHERE to_bot = $1 ORDER BY created_at DESC, delivery_id DESC LIMIT 1`,
      [botId],
    );
    return rows[0] ? mapDelivery(rows[0]) : null;
  }

  async peekNextDue(now: Date): Promise<DeliveryRow | null> {
    const rows = await this.db.query<Raw>(
      `SELECT * FROM notifier_deliveries
       WHERE status = 'pending' AND next_attempt_at <= $1
       ORDER BY next_attempt_at, delivery_id
       LIMIT 1
       FOR UPDATE SKIP LOCKED`,
      [now],
    );
    return rows[0] ? mapDelivery(rows[0]) : null;
  }

  async claimDelivery(deliveryId: string, now: Date, leaseUntil: Date): Promise<DeliveryRow | null> {
    const rows = await this.db.query<Raw>(
      `UPDATE notifier_deliveries
       SET attempts = attempts + 1, next_attempt_at = $3
       WHERE delivery_id = $1 AND status = 'pending' AND next_attempt_at <= $2
       RETURNING *`,
      [deliveryId, now, leaseUntil],
    );
    return rows[0] ? mapDelivery(rows[0]) : null;
  }

  async claimNextDue(now: Date, leaseUntil: Date): Promise<DeliveryRow | null> {
    const rows = await this.db.query<Raw>(
      `WITH due AS (
         SELECT delivery_id FROM notifier_deliveries
         WHERE status = 'pending' AND next_attempt_at <= $1
         ORDER BY next_attempt_at, delivery_id
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       UPDATE notifier_deliveries AS d
       SET attempts = d.attempts + 1, next_attempt_at = $2
       FROM due
       WHERE d.delivery_id = due.delivery_id
       RETURNING d.*`,
      [now, leaseUntil],
    );
    return rows[0] ? mapDelivery(rows[0]) : null;
  }

  async deferDelivery(deliveryId: string, nextAttemptAt: Date): Promise<void> {
    await this.db.query(
      `UPDATE notifier_deliveries SET next_attempt_at = $2 WHERE delivery_id = $1 AND status = 'pending'`,
      [deliveryId, nextAttemptAt],
    );
  }

  async finishDelivery(row: DeliveryRow): Promise<void> {
    await this.db.query(
      `UPDATE notifier_deliveries
       SET status = $2, attempts = $3, next_attempt_at = $4, last_status_code = $5, last_error = $6, delivered_at = $7
       WHERE delivery_id = $1`,
      [row.delivery_id, row.status, row.attempts, row.next_attempt_at, row.last_status_code, row.last_error, row.delivered_at],
    );
  }

  async cancelPendingForLink(linkId: string, reason: string): Promise<number> {
    const rows = await this.db.query(
      `UPDATE notifier_deliveries
       SET status = 'dead', last_error = $2
       WHERE status = 'pending' AND msg_id IN (SELECT msg_id FROM messages WHERE link_id = $1)
       RETURNING delivery_id`,
      [linkId, reason],
    );
    return rows.length;
  }

  async cancelPendingForBot(botId: string, reason: string): Promise<number> {
    const rows = await this.db.query(
      `UPDATE notifier_deliveries SET status = 'dead', last_error = $2
       WHERE status = 'pending' AND to_bot = $1
       RETURNING delivery_id`,
      [botId, reason],
    );
    return rows.length;
  }

  async countWebhookSendsSince(botId: string, since: Date, exceptDeliveryId?: string): Promise<number> {
    const params: unknown[] = [botId, since];
    let exclude = "";
    if (exceptDeliveryId) {
      params.push(exceptDeliveryId);
      exclude = ` AND delivery_id <> $${params.length}`;
    }
    const rows = await this.db.query<{ count: number | string }>(
      `SELECT COUNT(*)::int AS count FROM notifier_deliveries
       WHERE to_bot = $1 AND attempts > 0${exclude} AND (
         (delivered_at IS NOT NULL AND delivered_at >= $2) OR
         (delivered_at IS NULL AND next_attempt_at >= $2)
       )`,
      params,
    );
    return Number(rows[0]?.count ?? 0);
  }

  async insertAudit(row: AuditRow): Promise<void> {
    await this.db.query(
      `INSERT INTO audit_events (event_id, actor, action, link_id, meta_json, created_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
      [row.event_id, row.actor, row.action, row.link_id, JSON.stringify(row.meta_json), row.created_at],
    );
  }

  async countAuditsSince(actor: string, actions: string[], since: Date): Promise<number> {
    if (actions.length === 0) return 0;
    const params: unknown[] = [actor, since, ...actions];
    const placeholders = actions.map((_, index) => `$${index + 3}`).join(", ");
    const rows = await this.db.query<{ count: number | string }>(
      `SELECT COUNT(*)::int AS count FROM audit_events
       WHERE actor = $1 AND created_at > $2 AND action IN (${placeholders})`,
      params,
    );
    return Number(rows[0]?.count ?? 0);
  }

  async oldestAuditSince(actor: string, actions: string[], since: Date): Promise<Date | null> {
    if (actions.length === 0) return null;
    const params: unknown[] = [actor, since, ...actions];
    const placeholders = actions.map((_, index) => `$${index + 3}`).join(", ");
    const rows = await this.db.query<{ oldest: unknown }>(
      `SELECT MIN(created_at) AS oldest FROM audit_events
       WHERE actor = $1 AND created_at > $2 AND action IN (${placeholders})`,
      params,
    );
    return rows[0]?.oldest == null ? null : asDate(rows[0].oldest);
  }

  async listAudits(): Promise<AuditRow[]> {
    const rows = await this.db.query<Raw>("SELECT * FROM audit_events ORDER BY created_at ASC, event_id ASC");
    return rows.map(mapAudit);
  }
}

function inboxQuery(filter: InboxFilter, countOnly: boolean): { sql: string; params: unknown[] } {
  const params: unknown[] = [filter.toBot, filter.now];
  let where = `
    FROM messages m
    JOIN links l ON l.link_id = m.link_id
    WHERE m.to_bot = $1
      AND m.expires_at > $2
      AND l.status = 'active'
  `;
  if (filter.linkId) {
    params.push(filter.linkId);
    where += ` AND m.link_id = $${params.length}`;
  }
  if (filter.unreadOnly) where += " AND m.read_at IS NULL";
  if (filter.since) {
    params.push(filter.since);
    where += ` AND m.created_at > $${params.length}`;
  }
  if (filter.before) {
    params.push(filter.before.createdAt, filter.before.msgId);
    const at = params.length - 1;
    const id = params.length;
    where += ` AND (m.created_at < $${at} OR (m.created_at = $${at} AND m.msg_id < $${id}))`;
  }
  if (countOnly) return { sql: `SELECT COUNT(*)::int AS count ${where}`, params };
  params.push(filter.limit);
  return {
    sql: `SELECT m.* ${where} ORDER BY m.created_at DESC, m.msg_id DESC LIMIT $${params.length}`,
    params,
  };
}

function mapBot(row: Raw): BotRow {
  return {
    bot_id: String(row.bot_id),
    user_id: String(row.user_id),
    display_name: String(row.display_name),
    token_hash: String(row.token_hash),
    created_at: asDate(row.created_at),
  };
}

function mapLink(row: Raw): LinkRow {
  return {
    link_id: String(row.link_id),
    bot_a: String(row.bot_a),
    bot_b: row.bot_b == null ? null : String(row.bot_b),
    scope: "messages_only",
    status: row.status as LinkRow["status"],
    invite_code: String(row.invite_code),
    approved_a_at: asDateOrNull(row.approved_a_at),
    approved_b_at: asDateOrNull(row.approved_b_at),
    revoked_at: asDateOrNull(row.revoked_at),
    revoked_by: row.revoked_by == null ? null : String(row.revoked_by),
    created_at: asDate(row.created_at),
  };
}

function mapApproval(row: Raw): ApprovalRow {
  return {
    approval_id: String(row.approval_id),
    link_id: String(row.link_id),
    user_id: String(row.user_id),
    side: row.side as Side,
    token: String(row.token),
    expires_at: asDate(row.expires_at),
    consumed_at: asDateOrNull(row.consumed_at),
  };
}

function mapManage(row: Raw): ManageRow {
  return {
    link_id: String(row.link_id),
    bot_id: String(row.bot_id),
    token: String(row.token),
    created_at: asDate(row.created_at),
  };
}

function mapMessage(row: Raw): MessageRow {
  return {
    msg_id: String(row.msg_id),
    link_id: String(row.link_id),
    from_bot: String(row.from_bot),
    to_bot: String(row.to_bot),
    body: String(row.body),
    thread_id: String(row.thread_id),
    idempotency_key: row.idempotency_key == null ? null : String(row.idempotency_key),
    created_at: asDate(row.created_at),
    read_at: asDateOrNull(row.read_at),
    expires_at: asDate(row.expires_at),
  };
}

function mapSettings(row: Raw): SettingsTokenRow {
  return {
    bot_id: String(row.bot_id),
    token: String(row.token),
    created_at: asDate(row.created_at),
  };
}

function mapNotifier(row: Raw): NotifierRow {
  return {
    notifier_id: String(row.notifier_id),
    bot_id: String(row.bot_id),
    kind: "webhook",
    enabled: row.enabled === true || row.enabled === "t" || row.enabled === "true",
    url: row.url == null ? null : String(row.url),
    auth_scheme: row.auth_scheme as NotifierRow["auth_scheme"],
    secret_ciphertext: row.secret_ciphertext == null ? null : String(row.secret_ciphertext),
    secret_nonce: row.secret_nonce == null ? null : String(row.secret_nonce),
    secret_hint: row.secret_hint == null ? null : String(row.secret_hint),
    created_at: asDate(row.created_at),
    updated_at: asDate(row.updated_at),
    consecutive_auth_failures: Number(row.consecutive_auth_failures ?? 0),
    last_error: row.last_error == null ? null : String(row.last_error),
  };
}

function mapDelivery(row: Raw): DeliveryRow {
  return {
    delivery_id: String(row.delivery_id),
    msg_id: String(row.msg_id),
    notifier_id: String(row.notifier_id),
    to_bot: String(row.to_bot),
    status: row.status as DeliveryRow["status"],
    attempts: Number(row.attempts),
    next_attempt_at: asDate(row.next_attempt_at),
    last_status_code: row.last_status_code == null ? null : Number(row.last_status_code),
    last_error: row.last_error == null ? null : String(row.last_error),
    delivered_at: asDateOrNull(row.delivered_at),
    created_at: asDate(row.created_at),
  };
}

function mapAudit(row: Raw): AuditRow {
  return {
    event_id: String(row.event_id),
    actor: String(row.actor),
    action: String(row.action),
    link_id: row.link_id == null ? null : String(row.link_id),
    meta_json: asMeta(row.meta_json),
    created_at: asDate(row.created_at),
  };
}
