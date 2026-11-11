import { newId, randomToken } from "./ids.js";
import {
  DRIVE_CAPABILITIES,
  DRIVE_PROVIDER,
  driveAccessToken,
  driveAuthorizationUrl,
  driveScopeAllows,
  driveScopeFor,
  exchangeDriveCode,
  executeDriveTool,
  listDriveChildren,
} from "./providers/google-drive.js";
import { err, ok, type Result } from "./result.js";
import { decryptSecret, encryptSecret } from "./secret.js";
import type { Store } from "./store/types.js";
import type { BotRow, ConnectionRow, GrantRow } from "./types.js";

const DEFAULT_CAPABILITIES = ["list", "read"];
const KNOWN = new Set(DRIVE_CAPABILITIES.map((item) => item.id));

export type AccessCatalog = {
  integrations: Array<{
    provider: string;
    label: string;
    capabilities: string[];
    resources: Array<{ kind: "file" | "folder"; id: string; name: string }>;
  }>;
};

export type DriveClientConfig = { clientId: string; clientSecret: string };

type AccessOptions = {
  now?: () => Date;
  encryptionKey?: string;
  fetch?: typeof fetch;
  googleDrive?: DriveClientConfig | null;
};

export class Access {
  private readonly now: () => Date;
  private readonly fetchImpl: typeof fetch;
  private readonly encryptionKey: string;
  private readonly googleDrive: DriveClientConfig | null;

  constructor(
    private readonly store: Store,
    options: AccessOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.fetchImpl = options.fetch ?? fetch;
    this.encryptionKey = options.encryptionKey ?? "";
    this.googleDrive = options.googleDrive ?? null;
  }

  async catalog(bot: BotRow): Promise<Result<AccessCatalog>> {
    const connections = await this.store.listConnections(bot.bot_id);
    const integrations = [];
    for (const connection of connections) {
      if (connection.status !== "active" || connection.provider !== DRIVE_PROVIDER) continue;
      const capabilities = await this.store.listCapabilities(connection.connection_id);
      const grants = await this.store.listGrants(connection.connection_id);
      integrations.push({
        provider: connection.provider,
        label: "Google Drive",
        capabilities,
        resources: grants.map((grant) => ({ kind: grant.kind, id: grant.external_id, name: grant.name })),
      });
    }
    return ok({ integrations });
  }

  async toolNames(bot: BotRow): Promise<string[]> {
    const connection = await this.activeDrive(bot.bot_id);
    if (!connection) return [];
    const enabled = new Set(await this.store.listCapabilities(connection.connection_id));
    return DRIVE_CAPABILITIES.filter((item) => enabled.has(item.id)).flatMap((item) => [...item.tools]);
  }

  driveConnectUrl(input: { redirectUri: string; state: string; challenge: string; capabilities: string[] }): Result<string> {
    if (!this.googleDrive) return err("not_configured", "Google Drive login is not configured.");
    const capabilities = normalizeCapabilities(input.capabilities);
    return ok(driveAuthorizationUrl({ clientId: this.googleDrive.clientId, redirectUri: input.redirectUri, state: input.state, challenge: input.challenge, capabilities }));
  }

  async finishDriveConnect(input: { bot: BotRow; code: string; verifier: string; redirectUri: string; capabilities: string[] }): Promise<Result<{ connection_id: string }>> {
    if (!this.googleDrive) return err("not_configured", "Google Drive login is not configured.");
    if (!this.encryptionKey) return err("not_configured", "ENCRYPTION_KEY is required before a Drive credential can be stored.");
    let exchanged: { refreshToken: string; label: string; scope: string };
    try {
      exchanged = await exchangeDriveCode({ ...this.googleDrive, redirectUri: input.redirectUri, code: input.code, verifier: input.verifier, fetch: this.fetchImpl });
    } catch {
      return err("drive_connect_failed", "Google Drive did not return a credential.");
    }
    const requested = normalizeCapabilities(input.capabilities);
    const capabilities = requested.filter((id) => driveScopeAllows(exchanged.scope, [id]));
    const enabled = capabilities.length > 0 ? capabilities : DEFAULT_CAPABILITIES.filter((id) => driveScopeAllows(exchanged.scope, [id]));
    const now = this.now();
    const existing = await this.store.findConnection(input.bot.bot_id, DRIVE_PROVIDER);
    const connection: ConnectionRow = existing ?? {
      connection_id: newId("con"),
      bot_id: input.bot.bot_id,
      provider: DRIVE_PROVIDER,
      status: "active",
      credential_ciphertext: null,
      external_account_label: null,
      scope: null,
      created_at: now,
    };
    connection.status = "active";
    connection.credential_ciphertext = encryptSecret(this.encryptionKey, exchanged.refreshToken);
    connection.external_account_label = exchanged.label;
    connection.scope = exchanged.scope || driveScopeFor(enabled);
    if (existing) await this.store.updateConnection(connection);
    else {
      const inserted = await this.store.insertConnection(connection);
      if (inserted === "conflict") return err("conflict", "This bot already has a Google Drive card.");
    }
    await this.store.setCapabilities(connection.connection_id, enabled);
    return ok({ connection_id: connection.connection_id });
  }

  async setCapabilities(bot: BotRow, capabilityIds: string[]): Promise<Result<{ capabilities: string[] }>> {
    const connection = await this.activeDrive(bot.bot_id);
    if (!connection) return err("not_connected", "Connect Google Drive on this bot first.");
    const requested = [...new Set(capabilityIds.filter((id) => KNOWN.has(id as (typeof DRIVE_CAPABILITIES)[number]["id"])))];
    if (!driveScopeAllows(connection.scope, requested)) {
      return err("needs_reconnect", "Reconnect Google Drive and allow write access before enabling that action.");
    }
    await this.store.setCapabilities(connection.connection_id, requested);
    return ok({ capabilities: requested });
  }

  async grant(bot: BotRow, input: { kind: "file" | "folder"; externalId: string; name: string }): Promise<Result<{ grant_id: string }>> {
    const connection = await this.activeDrive(bot.bot_id);
    if (!connection) return err("not_connected", "Connect Google Drive on this bot first.");
    const grant: GrantRow = {
      grant_id: newId("gr"),
      connection_id: connection.connection_id,
      kind: input.kind,
      external_id: input.externalId,
      name: input.name.slice(0, 200) || input.externalId,
      granted_at: this.now(),
    };
    const inserted = await this.store.insertGrant(grant);
    if (inserted === "exists") {
      const current = await this.store.listGrants(connection.connection_id);
      const found = current.find((row) => row.external_id === input.externalId);
      return ok({ grant_id: found?.grant_id ?? grant.grant_id });
    }
    return ok({ grant_id: grant.grant_id });
  }

  async revokeGrant(bot: BotRow, grantId: string): Promise<Result<{ revoked: true }>> {
    const connection = await this.activeDrive(bot.bot_id);
    if (!connection) return err("not_connected", "Connect Google Drive on this bot first.");
    await this.store.deleteGrant(connection.connection_id, grantId);
    return ok({ revoked: true });
  }

  async browse(bot: BotRow, folderId?: string): Promise<Result<{ resources: Array<{ kind: "file" | "folder"; id: string; name: string }> }>> {
    const ready = await this.ready(bot.bot_id);
    if (!ready.ok) return ready;
    try {
      const children = await listDriveChildren(this.fetchImpl, ready.data.accessToken, folderId);
      return ok({ resources: children.map(({ kind, id, name }) => ({ kind, id, name })) });
    } catch {
      return err("drive_unavailable", "Google Drive could not be listed.");
    }
  }

  async call(bot: BotRow, tool: string, args: Record<string, unknown>, baseUrl: string): Promise<Result<unknown>> {
    const capability = DRIVE_CAPABILITIES.find((item) => (item.tools as readonly string[]).includes(tool));
    if (!capability) return err("unknown_tool", "This bot does not have that action.");
    const ready = await this.ready(bot.bot_id);
    if (!ready.ok) return ready;
    const enabled = await this.store.listCapabilities(ready.data.connection.connection_id);
    if (!enabled.includes(capability.id)) return err("capability_disabled", "That action is turned off on this bot's Google Drive card.");
    const grants = await this.store.listGrants(ready.data.connection.connection_id);
    let result: Result<unknown>;
    try {
      result = await executeDriveTool({ tool, args, accessToken: ready.data.accessToken, grants, fetch: this.fetchImpl });
    } catch {
      return err("drive_unavailable", "Google Drive could not complete that action.");
    }
    if (result.ok || result.error !== "access_required") return result;
    const externalId = String(result.details?.external_id ?? "");
    const kind = result.details?.kind === "folder" ? "folder" : "file";
    const approval = await this.ensureRequest(ready.data.connection, externalId, kind, capability.id);
    return err("access_required", result.message, { ...result.details, request_id: approval.request_id, approval_url: `${trimBase(baseUrl)}/access/${approval.approval_token}` });
  }

  async approvalFor(token: string, userId: string | null): Promise<Result<{ external_id: string; kind: string; status: string; bot_id: string }>> {
    const request = await this.store.findAccessRequestByToken(token);
    if (!request) return err("not_found", "This approval link is not valid.");
    const connection = await this.store.findConnectionById(request.connection_id);
    if (!connection) return err("not_found", "This approval link is not valid.");
    const bot = await this.store.findBotById(connection.bot_id);
    if (!bot || !userId || bot.user_id !== userId) return err("forbidden", "Sign in as the owner of this bot to approve access.");
    return ok({ external_id: request.external_id, kind: request.kind, status: request.status, bot_id: bot.bot_id });
  }

  async decideAccess(token: string, userId: string, decision: "approve" | "deny"): Promise<Result<{ status: string }>> {
    const view = await this.approvalFor(token, userId);
    if (!view.ok) return view;
    const request = await this.store.findAccessRequestByToken(token);
    if (!request) return err("not_found", "This approval link is not valid.");
    if (request.status !== "pending") return ok({ status: request.status });
    request.status = decision === "approve" ? "approved" : "denied";
    request.decided_at = this.now();
    await this.store.updateAccessRequest(request);
    if (decision === "approve") {
      await this.store.insertGrant({
        grant_id: newId("gr"),
        connection_id: request.connection_id,
        kind: request.kind,
        external_id: request.external_id,
        name: request.external_id,
        granted_at: this.now(),
      });
    }
    return ok({ status: request.status });
  }

  private async ensureRequest(connection: ConnectionRow, externalId: string, kind: "file" | "folder", capabilityId: string) {
    const pending = await this.store.findPendingAccessRequest(connection.connection_id, externalId);
    if (pending) return pending;
    const request = {
      request_id: newId("req"),
      connection_id: connection.connection_id,
      external_id: externalId,
      kind,
      capability_id: capabilityId,
      status: "pending" as const,
      approval_token: randomToken("ar_"),
      created_at: this.now(),
      decided_at: null,
    };
    await this.store.insertAccessRequest(request);
    return request;
  }

  private async activeDrive(botId: string): Promise<ConnectionRow | null> {
    const connection = await this.store.findConnection(botId, DRIVE_PROVIDER);
    if (!connection || connection.status !== "active") return null;
    return connection;
  }

  private async ready(botId: string): Promise<Result<{ connection: ConnectionRow; accessToken: string }>> {
    const connection = await this.activeDrive(botId);
    if (!connection) return err("not_connected", "This bot has no Google Drive card.");
    if (!this.googleDrive || !this.encryptionKey || !connection.credential_ciphertext) {
      return err("not_configured", "Google Drive credentials are not available.");
    }
    const refresh = decryptSecret(this.encryptionKey, connection.credential_ciphertext);
    if (!refresh) return err("not_configured", "The stored Drive credential could not be read.");
    try {
      const accessToken = await driveAccessToken({ ...this.googleDrive, refreshToken: refresh, fetch: this.fetchImpl });
      return ok({ connection, accessToken });
    } catch {
      return err("drive_unavailable", "Google Drive could not be reached.");
    }
  }
}

function normalizeCapabilities(ids: string[]): string[] {
  const selected = [...new Set(ids.filter((id) => KNOWN.has(id as (typeof DRIVE_CAPABILITIES)[number]["id"])))];
  return selected.length > 0 ? selected : [...DEFAULT_CAPABILITIES];
}

function trimBase(baseUrl: string): string {
  return baseUrl.replace(/\/$/, "");
}
