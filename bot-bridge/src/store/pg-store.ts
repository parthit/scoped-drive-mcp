import { schemaStatements } from "../schema.js";
import type { ApprovalRow, AuditRow, BotRow, InboxFilter, LinkRow, ManageRow, MessageRow, Side, UserRow } from "../types.js";
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
      "TRUNCATE TABLE audit_events, messages, manage_tokens, approvals, links, bots, users, rate_locks RESTART IDENTITY CASCADE",
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
