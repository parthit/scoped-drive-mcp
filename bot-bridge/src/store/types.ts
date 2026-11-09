import type {
  ApprovalRow,
  AuditRow,
  BotRow,
  InboxFilter,
  LinkRow,
  ManageRow,
  MessageRow,
  Side,
  UserRow,
} from "../types.js";

export interface Store {
  readonly kind: "memory" | "postgres";
  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T>;
  ping(): Promise<void>;
  clearAll(): Promise<void>;

  insertUser(row: UserRow): Promise<void>;
  insertBot(row: BotRow): Promise<void>;
  findBotByTokenHash(hash: string): Promise<BotRow | null>;
  findBotById(id: string): Promise<BotRow | null>;
  lockBot(botId: string): Promise<void>;

  insertLink(row: LinkRow): Promise<"ok" | "conflict">;
  findLinkById(id: string): Promise<LinkRow | null>;
  findLinkByInvite(code: string): Promise<LinkRow | null>;
  lockLink(id: string): Promise<LinkRow | null>;
  listLinksForBot(botId: string): Promise<LinkRow[]>;
  attachPeer(linkId: string, botId: string): Promise<LinkRow | null>;
  markApproved(linkId: string, side: Side, at: Date): Promise<LinkRow | null>;
  revoke(linkId: string, at: Date, by: string): Promise<LinkRow | null>;

  insertApproval(row: ApprovalRow): Promise<"ok" | "conflict">;
  findOpenApproval(linkId: string, side: Side): Promise<ApprovalRow | null>;
  findApprovalByToken(token: string): Promise<ApprovalRow | null>;
  updateApproval(row: ApprovalRow): Promise<ApprovalRow | null>;
  consumeApproval(approvalId: string, at: Date): Promise<ApprovalRow | null>;

  insertManageToken(row: ManageRow): Promise<"ok" | "exists">;
  findManageToken(linkId: string, botId: string): Promise<ManageRow | null>;
  findManageByToken(token: string): Promise<ManageRow | null>;

  insertMessage(row: MessageRow): Promise<"ok" | "conflict">;
  findMessageById(id: string): Promise<MessageRow | null>;
  findMessageByIdempotency(fromBot: string, key: string): Promise<MessageRow | null>;
  listInbox(filter: InboxFilter): Promise<MessageRow[]>;
  countInbox(filter: Omit<InboxFilter, "limit" | "before">): Promise<number>;
  countSentSince(botId: string, since: Date, linkId?: string): Promise<number>;
  oldestSentSince(botId: string, since: Date, linkId?: string): Promise<Date | null>;
  markMessagesRead(botId: string, ids: string[], now: Date): Promise<number>;
  deleteMessagesForLink(linkId: string): Promise<number>;
  deleteExpiredMessages(now: Date): Promise<number>;
  threadLinkIds(threadId: string): Promise<string[]>;
  messagesInThreadForBot(threadId: string, botId: string, now: Date): Promise<MessageRow[]>;

  insertAudit(row: AuditRow): Promise<void>;
  countAuditsSince(actor: string, actions: string[], since: Date): Promise<number>;
  oldestAuditSince(actor: string, actions: string[], since: Date): Promise<Date | null>;
  listAudits(): Promise<AuditRow[]>;
}
