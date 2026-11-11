import { deriveStatus, type ApprovalRow, type AuditRow, type BotRow, type DeliveryRow, type InboxFilter, type LinkRow, type ManageRow, type MessageRow, type NotifierKind, type NotifierRow, type SettingsTokenRow, type Side, type UserRow } from "../types.js";
import type { Store } from "./types.js";

function copy<T>(row: T): T {
  return { ...row };
}

export class MemoryStore implements Store {
  readonly kind = "memory" as const;
  private queue: Promise<void> = Promise.resolve();
  private users = new Map<string, UserRow>();
  private bots = new Map<string, BotRow>();
  private botsByHash = new Map<string, string>();
  private links = new Map<string, LinkRow>();
  private approvals = new Map<string, ApprovalRow>();
  private manage = new Map<string, ManageRow>();
  private messages = new Map<string, MessageRow>();
  private settings = new Map<string, SettingsTokenRow>();
  private notifiers = new Map<string, NotifierRow>();
  private deliveries = new Map<string, DeliveryRow>();
  private audits: AuditRow[] = [];
  private rates = new Map<string, { windowStart: number; hits: number }>();

  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T> {
    const run = this.queue.then(() => fn(this));
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async ping(): Promise<void> {}

  async clearAll(): Promise<void> {
    this.users.clear();
    this.bots.clear();
    this.botsByHash.clear();
    this.links.clear();
    this.approvals.clear();
    this.manage.clear();
    this.messages.clear();
    this.settings.clear();
    this.notifiers.clear();
    this.deliveries.clear();
    this.audits = [];
    this.rates.clear();
  }

  async insertUser(row: UserRow): Promise<void> {
    this.users.set(row.user_id, copy(row));
  }

  async insertBot(row: BotRow): Promise<void> {
    this.bots.set(row.bot_id, copy(row));
    this.botsByHash.set(row.token_hash, row.bot_id);
  }

  async findBotByTokenHash(hash: string): Promise<BotRow | null> {
    const id = this.botsByHash.get(hash);
    if (!id) return null;
    const bot = this.bots.get(id);
    return bot ? copy(bot) : null;
  }

  async findBotById(id: string): Promise<BotRow | null> {
    const bot = this.bots.get(id);
    return bot ? copy(bot) : null;
  }

  async lockBot(_botId: string): Promise<void> {}

  async insertLink(row: LinkRow): Promise<"ok" | "conflict"> {
    for (const existing of this.links.values()) {
      if (existing.invite_code === row.invite_code) return "conflict";
    }
    this.links.set(row.link_id, copy(row));
    return "ok";
  }

  async findLinkById(id: string): Promise<LinkRow | null> {
    const link = this.links.get(id);
    return link ? copy(link) : null;
  }

  async findLinkByInvite(code: string): Promise<LinkRow | null> {
    for (const link of this.links.values()) {
      if (link.invite_code === code) return copy(link);
    }
    return null;
  }

  async lockLink(id: string): Promise<LinkRow | null> {
    return this.findLinkById(id);
  }

  async listLinksForBot(botId: string): Promise<LinkRow[]> {
    return [...this.links.values()]
      .filter((link) => link.bot_a === botId || link.bot_b === botId)
      .sort((a, b) => b.created_at.getTime() - a.created_at.getTime() || (a.link_id < b.link_id ? 1 : -1))
      .map((link) => copy(link));
  }

  async attachPeer(linkId: string, botId: string): Promise<LinkRow | null> {
    const link = this.links.get(linkId);
    if (!link || link.bot_b || link.revoked_at || link.bot_a === botId) return null;
    link.bot_b = botId;
    link.status = deriveStatus(link);
    return copy(link);
  }

  async markApproved(linkId: string, side: Side, at: Date): Promise<LinkRow | null> {
    const link = this.links.get(linkId);
    if (!link || link.revoked_at) return null;
    if (side === "a") link.approved_a_at = link.approved_a_at ?? at;
    else link.approved_b_at = link.approved_b_at ?? at;
    link.status = deriveStatus(link);
    return copy(link);
  }

  async revoke(linkId: string, at: Date, by: string): Promise<LinkRow | null> {
    const link = this.links.get(linkId);
    if (!link) return null;
    if (!link.revoked_at) {
      link.revoked_at = at;
      link.revoked_by = by;
    }
    link.status = "revoked";
    return copy(link);
  }

  async insertApproval(row: ApprovalRow): Promise<"ok" | "conflict"> {
    for (const existing of this.approvals.values()) {
      if (existing.token === row.token) return "conflict";
      if (existing.link_id === row.link_id && existing.side === row.side && existing.consumed_at == null && row.consumed_at == null) {
        return "conflict";
      }
    }
    this.approvals.set(row.approval_id, copy(row));
    return "ok";
  }

  async findOpenApproval(linkId: string, side: Side): Promise<ApprovalRow | null> {
    const open = [...this.approvals.values()]
      .filter((row) => row.link_id === linkId && row.side === side && row.consumed_at == null)
      .sort((a, b) => b.expires_at.getTime() - a.expires_at.getTime());
    return open[0] ? copy(open[0]) : null;
  }

  async findApprovalByToken(token: string): Promise<ApprovalRow | null> {
    for (const row of this.approvals.values()) {
      if (row.token === token) return copy(row);
    }
    return null;
  }

  async updateApproval(row: ApprovalRow): Promise<ApprovalRow | null> {
    const current = this.approvals.get(row.approval_id);
    if (!current || current.consumed_at) return null;
    const next: ApprovalRow = { ...current, token: row.token, expires_at: row.expires_at };
    this.approvals.set(row.approval_id, next);
    return copy(next);
  }

  async consumeApproval(approvalId: string, at: Date): Promise<ApprovalRow | null> {
    const row = this.approvals.get(approvalId);
    if (!row || row.consumed_at) return null;
    row.consumed_at = at;
    return copy(row);
  }

  async insertManageToken(row: ManageRow): Promise<"ok" | "exists"> {
    const key = `${row.link_id}:${row.bot_id}`;
    if (this.manage.has(key)) return "exists";
    for (const existing of this.manage.values()) {
      if (existing.token === row.token) return "exists";
    }
    this.manage.set(key, copy(row));
    return "ok";
  }

  async findManageToken(linkId: string, botId: string): Promise<ManageRow | null> {
    const row = this.manage.get(`${linkId}:${botId}`);
    return row ? copy(row) : null;
  }

  async findManageByToken(token: string): Promise<ManageRow | null> {
    for (const row of this.manage.values()) {
      if (row.token === token) return copy(row);
    }
    return null;
  }

  async insertMessage(row: MessageRow): Promise<"ok" | "conflict"> {
    if (row.idempotency_key) {
      for (const existing of this.messages.values()) {
        if (existing.from_bot === row.from_bot && existing.idempotency_key === row.idempotency_key) return "conflict";
      }
    }
    this.messages.set(row.msg_id, copy(row));
    return "ok";
  }

  async findMessageById(id: string): Promise<MessageRow | null> {
    const row = this.messages.get(id);
    return row ? copy(row) : null;
  }

  async findMessageByIdempotency(fromBot: string, key: string): Promise<MessageRow | null> {
    for (const row of this.messages.values()) {
      if (row.from_bot === fromBot && row.idempotency_key === key) return copy(row);
    }
    return null;
  }

  async listInbox(filter: InboxFilter): Promise<MessageRow[]> {
    return this.inboxRows(filter).slice(0, filter.limit);
  }

  async countInbox(filter: Omit<InboxFilter, "limit" | "before">): Promise<number> {
    return this.inboxRows({ ...filter, limit: Number.MAX_SAFE_INTEGER }).length;
  }

  private inboxRows(filter: InboxFilter): MessageRow[] {
    const rows = [...this.messages.values()].filter((message) => {
      if (message.to_bot !== filter.toBot) return false;
      if (message.expires_at <= filter.now) return false;
      const link = this.links.get(message.link_id);
      if (!link || link.status !== "active") return false;
      if (filter.linkId && message.link_id !== filter.linkId) return false;
      if (filter.unreadOnly && message.read_at) return false;
      if (filter.since && message.created_at <= filter.since) return false;
      if (filter.before && !isBeforeCursor(message, filter.before)) return false;
      return true;
    });
    rows.sort(compareInboxDesc);
    return rows.map((row) => copy(row));
  }

  async countSentSince(botId: string, since: Date, linkId?: string): Promise<number> {
    let count = 0;
    for (const message of this.messages.values()) {
      if (message.from_bot !== botId || message.created_at <= since) continue;
      if (linkId && message.link_id !== linkId) continue;
      count += 1;
    }
    return count;
  }

  async oldestSentSince(botId: string, since: Date, linkId?: string): Promise<Date | null> {
    let oldest: Date | null = null;
    for (const message of this.messages.values()) {
      if (message.from_bot !== botId || message.created_at <= since) continue;
      if (linkId && message.link_id !== linkId) continue;
      if (!oldest || message.created_at < oldest) oldest = message.created_at;
    }
    return oldest ? new Date(oldest.getTime()) : null;
  }

  async markMessagesRead(botId: string, ids: string[], now: Date): Promise<number> {
    let marked = 0;
    for (const id of ids) {
      const message = this.messages.get(id);
      if (!message || message.to_bot !== botId || message.read_at || message.expires_at <= now) continue;
      const link = this.links.get(message.link_id);
      if (!link || link.status !== "active") continue;
      message.read_at = now;
      marked += 1;
    }
    return marked;
  }

  async deleteMessagesForLink(linkId: string): Promise<number> {
    const ids = new Set<string>();
    for (const [id, message] of this.messages) {
      if (message.link_id === linkId) ids.add(id);
    }
    return this.deleteMessageIds(ids);
  }

  async deleteExpiredMessages(now: Date): Promise<number> {
    const ids = new Set<string>();
    for (const [id, message] of this.messages) {
      if (message.expires_at <= now) ids.add(id);
    }
    return this.deleteMessageIds(ids);
  }

  private deleteMessageIds(ids: Set<string>): number {
    for (const id of ids) this.messages.delete(id);
    for (const [id, delivery] of this.deliveries) {
      if (ids.has(delivery.msg_id)) this.deliveries.delete(id);
    }
    return ids.size;
  }

  async threadLinkIds(threadId: string): Promise<string[]> {
    const ids = new Set<string>();
    for (const message of this.messages.values()) {
      if (message.thread_id === threadId) ids.add(message.link_id);
    }
    return [...ids];
  }

  async messagesInThreadForBot(threadId: string, botId: string, now: Date): Promise<MessageRow[]> {
    return [...this.messages.values()]
      .filter(
        (message) =>
          message.thread_id === threadId &&
          message.expires_at > now &&
          (message.from_bot === botId || message.to_bot === botId),
      )
      .sort((a, b) => b.created_at.getTime() - a.created_at.getTime())
      .slice(0, 20)
      .map((row) => copy(row));
  }

  async tryConsumeRate(actor: string, now: Date, windowMs: number, limit: number): Promise<boolean> {
    const cutoff = now.getTime() - windowMs;
    const current = this.rates.get(actor);
    if (!current || current.windowStart <= cutoff) {
      this.rates.set(actor, { windowStart: now.getTime(), hits: 1 });
      return true;
    }
    if (current.hits >= limit) return false;
    current.hits += 1;
    return true;
  }

  async insertSettingsToken(row: SettingsTokenRow): Promise<"ok" | "exists"> {
    if (this.settings.has(row.bot_id)) return "exists";
    for (const existing of this.settings.values()) {
      if (existing.token === row.token) return "exists";
    }
    this.settings.set(row.bot_id, copy(row));
    return "ok";
  }

  async findSettingsTokenByBot(botId: string): Promise<SettingsTokenRow | null> {
    const row = this.settings.get(botId);
    return row ? copy(row) : null;
  }

  async findSettingsTokenByToken(token: string): Promise<SettingsTokenRow | null> {
    for (const row of this.settings.values()) {
      if (row.token === token) return copy(row);
    }
    return null;
  }

  async rotateSettingsToken(botId: string, token: string, at: Date): Promise<SettingsTokenRow | null> {
    const row = this.settings.get(botId);
    if (!row) return null;
    row.token = token;
    row.created_at = at;
    return copy(row);
  }

  async upsertNotifier(row: NotifierRow): Promise<NotifierRow> {
    const existing = [...this.notifiers.values()].find((item) => item.bot_id === row.bot_id && item.kind === row.kind);
    if (!existing) {
      this.notifiers.set(row.notifier_id, copy(row));
      return copy(row);
    }
    const next: NotifierRow = {
      ...existing,
      enabled: row.enabled,
      url: row.url,
      auth_scheme: row.auth_scheme,
      secret_ciphertext: row.secret_ciphertext,
      secret_nonce: row.secret_nonce,
      secret_hint: row.secret_hint,
      updated_at: row.updated_at,
      consecutive_auth_failures: 0,
      last_error: null,
    };
    this.notifiers.set(existing.notifier_id, next);
    return copy(next);
  }

  async findNotifier(botId: string, kind: NotifierKind): Promise<NotifierRow | null> {
    for (const row of this.notifiers.values()) {
      if (row.bot_id === botId && row.kind === kind) return copy(row);
    }
    return null;
  }

  async deleteNotifier(botId: string, kind: NotifierKind): Promise<boolean> {
    const existing = [...this.notifiers.values()].find((item) => item.bot_id === botId && item.kind === kind);
    if (!existing) return false;
    this.notifiers.delete(existing.notifier_id);
    for (const [id, delivery] of this.deliveries) {
      if (delivery.notifier_id === existing.notifier_id) this.deliveries.delete(id);
    }
    return true;
  }

  async setNotifierHealth(
    notifierId: string,
    input: { enabled: boolean; consecutiveAuthFailures: number; lastError: string | null },
  ): Promise<void> {
    const row = this.notifiers.get(notifierId);
    if (!row) return;
    row.enabled = input.enabled;
    row.consecutive_auth_failures = input.consecutiveAuthFailures;
    row.last_error = input.lastError;
  }

  async insertDelivery(row: DeliveryRow): Promise<"ok" | "conflict"> {
    for (const existing of this.deliveries.values()) {
      if (existing.msg_id === row.msg_id) return "conflict";
    }
    this.deliveries.set(row.delivery_id, copy(row));
    return "ok";
  }

  async findDelivery(deliveryId: string): Promise<DeliveryRow | null> {
    const row = this.deliveries.get(deliveryId);
    return row ? copy(row) : null;
  }

  async latestDelivery(botId: string): Promise<DeliveryRow | null> {
    const rows = [...this.deliveries.values()].filter((row) => row.to_bot === botId);
    rows.sort((a, b) => b.created_at.getTime() - a.created_at.getTime() || (a.delivery_id < b.delivery_id ? 1 : -1));
    return rows[0] ? copy(rows[0]) : null;
  }

  async peekNextDue(now: Date): Promise<DeliveryRow | null> {
    const due = [...this.deliveries.values()]
      .filter((row) => row.status === "pending" && row.next_attempt_at <= now)
      .sort((a, b) => a.next_attempt_at.getTime() - b.next_attempt_at.getTime() || (a.delivery_id < b.delivery_id ? -1 : 1));
    return due[0] ? copy(due[0]) : null;
  }

  async claimDelivery(deliveryId: string, now: Date, leaseUntil: Date): Promise<DeliveryRow | null> {
    const row = this.deliveries.get(deliveryId);
    if (!row || row.status !== "pending" || row.next_attempt_at > now) return null;
    row.attempts += 1;
    row.next_attempt_at = leaseUntil;
    return copy(row);
  }

  async claimNextDue(now: Date, leaseUntil: Date): Promise<DeliveryRow | null> {
    const due = [...this.deliveries.values()]
      .filter((row) => row.status === "pending" && row.next_attempt_at <= now)
      .sort((a, b) => a.next_attempt_at.getTime() - b.next_attempt_at.getTime() || (a.delivery_id < b.delivery_id ? -1 : 1));
    const row = due[0];
    if (!row) return null;
    return this.claimDelivery(row.delivery_id, now, leaseUntil);
  }

  async deferDelivery(deliveryId: string, nextAttemptAt: Date): Promise<void> {
    const row = this.deliveries.get(deliveryId);
    if (!row || row.status !== "pending") return;
    row.next_attempt_at = nextAttemptAt;
  }

  async finishDelivery(row: DeliveryRow): Promise<void> {
    const current = this.deliveries.get(row.delivery_id);
    if (!current) return;
    current.status = row.status;
    current.attempts = row.attempts;
    current.next_attempt_at = row.next_attempt_at;
    current.last_status_code = row.last_status_code;
    current.last_error = row.last_error;
    current.delivered_at = row.delivered_at;
  }

  async cancelPendingForLink(linkId: string, reason: string): Promise<number> {
    const messageIds = new Set([...this.messages.values()].filter((message) => message.link_id === linkId).map((message) => message.msg_id));
    let count = 0;
    for (const delivery of this.deliveries.values()) {
      if (delivery.status === "pending" && messageIds.has(delivery.msg_id)) {
        delivery.status = "dead";
        delivery.last_error = reason;
        count += 1;
      }
    }
    return count;
  }

  async cancelPendingForBot(botId: string, reason: string): Promise<number> {
    let count = 0;
    for (const delivery of this.deliveries.values()) {
      if (delivery.status === "pending" && delivery.to_bot === botId) {
        delivery.status = "dead";
        delivery.last_error = reason;
        count += 1;
      }
    }
    return count;
  }

  async countWebhookSendsSince(botId: string, since: Date, exceptDeliveryId?: string): Promise<number> {
    let count = 0;
    for (const delivery of this.deliveries.values()) {
      if (delivery.delivery_id === exceptDeliveryId) continue;
      if (delivery.to_bot !== botId || delivery.attempts < 1) continue;
      if (delivery.delivered_at) {
        if (delivery.delivered_at >= since) count += 1;
      } else if (delivery.created_at >= since) {
        count += 1;
      }
    }
    return count;
  }

  async insertAudit(row: AuditRow): Promise<void> {
    this.audits.push(copy(row));
  }

  async countAuditsSince(actor: string, actions: string[], since: Date): Promise<number> {
    return this.audits.filter((row) => row.actor === actor && row.created_at > since && actions.includes(row.action)).length;
  }

  async oldestAuditSince(actor: string, actions: string[], since: Date): Promise<Date | null> {
    let oldest: Date | null = null;
    for (const row of this.audits) {
      if (row.actor !== actor || row.created_at <= since || !actions.includes(row.action)) continue;
      if (!oldest || row.created_at < oldest) oldest = row.created_at;
    }
    return oldest ? new Date(oldest.getTime()) : null;
  }

  async listAudits(): Promise<AuditRow[]> {
    return this.audits.map((row) => ({ ...row, meta_json: { ...row.meta_json } }));
  }
}

function isBeforeCursor(message: MessageRow, before: { createdAt: Date; msgId: string }): boolean {
  const delta = message.created_at.getTime() - before.createdAt.getTime();
  if (delta < 0) return true;
  if (delta > 0) return false;
  return message.msg_id < before.msgId;
}

function compareInboxDesc(a: MessageRow, b: MessageRow): number {
  const delta = b.created_at.getTime() - a.created_at.getTime();
  if (delta !== 0) return delta;
  return a.msg_id < b.msg_id ? 1 : a.msg_id > b.msg_id ? -1 : 0;
}
