import { getCookie, setCookie } from "hono/cookie";
import { cors } from "hono/cors";
import { Hono, type Context } from "hono";
import { Access, type DriveClientConfig } from "./access.js";
import { Accounts } from "./accounts.js";
import { Bridge } from "./bridge.js";
import type { Scheduler } from "./background.js";
import type { WebhookTransport } from "./notify/webhook.js";
import type { DnsLookup } from "./ssrf.js";
import { createMcpServer } from "./mcp.js";
import { authorizationUrl, codeChallenge, codeVerifier, exchangeCode, isLoginProvider, type OAuthConfig } from "./oauth.js";
import {
  accessRequestPage,
  accountPage,
  approvalPage,
  approvalResultPage,
  botPage,
  driveBrowsePage,
  homePage,
  loginPage,
  manageDonePage,
  managePage,
  messagePage,
  playbookPage,
  registerPage,
  registeredPage,
  settingsPage,
  settingsRotatedPage,
} from "./pages.js";
import { newCsrf, openSealed, openSession, seal, type SessionPayload } from "./session.js";
import { PLAYBOOK } from "./playbook.js";
import { safeEqual, sha256 } from "./ids.js";
import { limitsFromEnv, webhookFeatureFromEnv, type Limits, type WebhookFeature } from "./limits.js";
import { createDefaultStore, type Store } from "./store/index.js";
import type { BotRow } from "./types.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";

const VERSION = "1.0.0";

export type AppDeps = {
  store: Store;
  now?: () => Date;
  limits?: Limits;
  baseUrl?: string;
  auditToken?: string | null;
  sweepToken?: string | null;
  webhookDrainToken?: string | null;
  cronSecret?: string | null;
  webhooks?: WebhookFeature;
  lookup?: DnsLookup;
  postWebhook?: WebhookTransport;
  schedule?: Scheduler;
  registerPerHour?: number;
  sessionSecret?: string | null;
  oauth?: OAuthConfig;
  fetch?: typeof fetch;
  encryptionKey?: string | null;
  googleDrive?: DriveClientConfig | null;
};

export function createApp(deps: AppDeps): Hono {
  const bridge = new Bridge(deps.store, {
    now: deps.now,
    limits: deps.limits,
    webhooks: deps.webhooks,
    lookup: deps.lookup,
    postWebhook: deps.postWebhook,
    schedule: deps.schedule,
  });
  const accounts = new Accounts(deps.store, deps.now);
  const oauth = deps.oauth ?? oauthFromEnv();
  const sessionSecret = deps.sessionSecret !== undefined ? deps.sessionSecret : process.env.SESSION_SECRET?.trim() || null;
  const fetchImpl = deps.fetch ?? fetch;
  const googleDrive = deps.googleDrive !== undefined ? deps.googleDrive : driveClientFromEnv(oauth);
  const access = new Access(deps.store, {
    now: deps.now,
    encryptionKey: deps.encryptionKey !== undefined ? deps.encryptionKey ?? "" : process.env.ENCRYPTION_KEY?.trim() || "",
    fetch: fetchImpl,
    googleDrive,
  });
  const auditToken = deps.auditToken !== undefined ? deps.auditToken : process.env.AUDIT_TOKEN?.trim() || null;
  const sweepToken = deps.sweepToken !== undefined ? deps.sweepToken : process.env.SWEEP_TOKEN?.trim() || null;
  const webhookDrainToken = deps.webhookDrainToken !== undefined ? deps.webhookDrainToken : process.env.WEBHOOK_DRAIN_TOKEN?.trim() || null;
  const cronSecret = deps.cronSecret !== undefined ? deps.cronSecret : process.env.CRON_SECRET?.trim() || null;
  const registerPerHour = deps.registerPerHour ?? 30;
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Frame-Options", "DENY");
  });

  const corsMw = cors({
    origin: "*",
    allowMethods: ["POST", "GET", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Accept", "Authorization", "Mcp-Protocol-Version", "Mcp-Session-Id", "Last-Event-ID", "X-Bot-Token"],
    exposeHeaders: ["Mcp-Session-Id", "WWW-Authenticate"],
    maxAge: 86400,
  });
  app.use("/mcp", corsMw);
  app.use("/mcp/*", corsMw);

  app.get("/", async (c) => {
    const session = readSession(c, sessionSecret);
    if (!session) return html(c, homePage());
    const bots = await deps.store.listBotsForUser(session.user_id);
    return html(c, accountPage(bots.map((bot) => ({ bot_id: bot.bot_id, display_name: bot.display_name }))));
  });

  app.get("/login", (c) => html(c, loginPage(loginLinks(oauth))));

  app.post("/logout", (c) => {
    setCookie(c, "bb_session", "", cookieOptions(base(c, deps.baseUrl), 0));
    return c.redirect("/", 303);
  });

  app.get("/auth/:provider", (c) => {
    const provider = c.req.param("provider");
    if (!isLoginProvider(provider) || !oauth[provider] || !sessionSecret) {
      return html(c, loginPage(loginLinks(oauth), "That login is not configured."), 400);
    }
    const verifier = codeVerifier();
    const state = seal(sessionSecret, { provider, verifier, exp: Date.now() + 10 * 60 * 1000, purpose: "login" });
    setCookie(c, "bb_oauth", state, cookieOptions(base(c, deps.baseUrl), 600));
    const redirectUri = `${base(c, deps.baseUrl)}/auth/${provider}/callback`;
    return c.redirect(authorizationUrl(provider, oauth[provider], redirectUri, state, codeChallenge(verifier)), 302);
  });

  app.get("/auth/:provider/callback", async (c) => {
    const provider = c.req.param("provider");
    if (!isLoginProvider(provider) || !oauth[provider] || !sessionSecret) {
      return html(c, messagePage("Sign-in failed", "That login is not configured."), 400);
    }
    const sealed = getCookie(c, "bb_oauth") ?? "";
    const pending = openOAuthState(sessionSecret, sealed);
    const state = c.req.query("state") ?? "";
    const code = c.req.query("code") ?? "";
    if (!pending || pending.provider !== provider || pending.purpose !== "login" || state !== sealed || !code) {
      return html(c, messagePage("Sign-in failed", "Start the sign-in again."), 400);
    }
    let profile;
    try {
      profile = await exchangeCode(provider, oauth[provider], `${base(c, deps.baseUrl)}/auth/${provider}/callback`, code, pending.verifier, fetchImpl);
    } catch {
      return html(c, messagePage("Sign-in failed", "The login provider did not confirm this account."), 400);
    }
    const current = readSession(c, sessionSecret);
    const result = await accounts.completeLogin(profile, current?.user_id ?? null);
    setCookie(c, "bb_oauth", "", cookieOptions(base(c, deps.baseUrl), 0));
    if (!result.ok) return html(c, messagePage("Sign-in failed", result.message), 409);
    const payload: SessionPayload = { user_id: result.data.user_id, csrf: newCsrf(), exp: Date.now() + 8 * 60 * 60 * 1000 };
    setCookie(c, "bb_session", seal(sessionSecret, payload), cookieOptions(base(c, deps.baseUrl), 8 * 60 * 60));
    return c.redirect("/", 303);
  });
  app.get("/playbook", (c) => {
    if (wantsJson(c)) return c.text(PLAYBOOK);
    return html(c, playbookPage());
  });

  app.get("/health", async (c) => {
    try {
      await deps.store.ping();
      return c.json({ ok: true, service: "bot-bridge", version: VERSION, store: deps.store.kind });
    } catch {
      return c.json({ ok: false, service: "bot-bridge", version: VERSION, store: deps.store.kind }, 503);
    }
  });

  app.get("/register", (c) => {
    if (!readSession(c, sessionSecret)) return c.redirect("/login", 303);
    return html(c, registerPage());
  });
  app.post("/register", async (c) => {
    const session = readSession(c, sessionSecret);
    if (!session) {
      if (wantsJson(c)) return c.json({ error: "account_required", message: "Sign in before creating a bot." }, 401);
      return c.redirect("/login", 303);
    }
    if (!(await allowRegister(deps.store, clientIp(c), registerPerHour, new Date()))) {
      const message = "Too many registrations from this network. Try again later.";
      if (wantsJson(c)) return c.json({ error: "rate_limited", message }, 429);
      return html(c, registerPage(message), 429);
    }
    const body = await readObject(c);
    if (!body.ok) {
      if (wantsJson(c)) return c.json({ error: "invalid_input", message: body.message }, 400);
      return html(c, registerPage(body.message), 400);
    }
    const result = await bridge.register(
      { displayName: stringField(body.value, "display_name") ?? stringField(body.value, "displayName") ?? "", userId: session.user_id },
      base(c, deps.baseUrl),
    );
    if (!result.ok) {
      if (wantsJson(c)) return c.json({ error: result.error, message: result.message }, 400);
      return html(c, registerPage(result.message), 400);
    }
    if (wantsJson(c)) return c.json(result.data, 201);
    return html(
      c,
      registeredPage({ displayName: result.data.display_name, mcpUrl: result.data.mcp_url, token: result.data.token, baseUrl: base(c, deps.baseUrl) }),
      201,
    );
  });

  app.get("/approve/:token", async (c) => {
    const view = await bridge.approvalView(c.req.param("token"), base(c, deps.baseUrl));
    return html(c, approvalPage(view));
  });

  app.post("/approve/:token", async (c) => {
    const token = c.req.param("token");
    const body = await readObject(c);
    const decision = body.ok ? stringField(body.value, "decision") : null;
    if (decision !== "approve" && decision !== "deny") {
      const message = "Choose approve or deny.";
      if (wantsJson(c)) return c.json({ error: "invalid_input", message }, 400);
      return html(c, messagePage("Missing decision", message), 400);
    }
    const result = await bridge.decideApproval(token, decision, base(c, deps.baseUrl));
    if (!result.ok) {
      if (wantsJson(c)) return c.json({ error: result.error, message: result.message, ...result.details }, statusFor(result.error));
      if (result.error === "waiting_for_peer") return html(c, approvalPage(await bridge.approvalView(token, base(c, deps.baseUrl))), 409);
      return html(c, messagePage("Approval not recorded", result.message), statusFor(result.error));
    }
    const view = await bridge.approvalView(token, base(c, deps.baseUrl));
    const peerName = view.state === "invalid" ? null : view.peer_name;
    if (wantsJson(c)) return c.json({ ...result.data, peer_name: peerName });
    return html(c, approvalResultPage({ status: result.data.status, peerName, manageUrl: result.data.manage_url, denied: decision === "deny" }));
  });

  app.get("/manage/:token", async (c) => html(c, managePage(await bridge.manageView(c.req.param("token")))));

  app.post("/manage/:token", async (c) => {
    const body = await readObject(c);
    const purge = body.ok && (body.value.purge_messages === true || body.value.purge_messages === "true" || body.value.purge_messages === "on");
    const result = await bridge.revokeFromManage(c.req.param("token"), purge);
    if (!result.ok) {
      if (wantsJson(c)) return c.json({ error: result.error, message: result.message }, statusFor(result.error));
      return html(c, managePage(await bridge.manageView(c.req.param("token")), result.message), statusFor(result.error));
    }
    if (wantsJson(c)) return c.json(result.data);
    return html(c, manageDonePage(result.data.purged_messages));
  });

  app.get("/audit", async (c) => {
    if (!auditToken) return c.json({ error: "not_found", message: "Audit read is disabled." }, 404);
    if (!bearerMatches(c.req.header("authorization"), auditToken)) {
      return c.json({ error: "unauthenticated", message: "Audit token required." }, 401);
    }
    const events = await deps.store.listAudits();
    return c.json({
      events: events.map((event) => ({
        event_id: event.event_id,
        actor: event.actor,
        action: event.action,
        link_id: event.link_id,
        meta: event.meta_json,
        created_at: event.created_at.toISOString(),
      })),
    });
  });

  app.post("/internal/sweep", async (c) => {
    if (!sweepToken) return c.json({ error: "not_found", message: "Sweep is disabled." }, 404);
    if (!bearerMatches(c.req.header("authorization"), sweepToken)) {
      return c.json({ error: "unauthenticated", message: "Sweep token required." }, 401);
    }
    return c.json(await bridge.sweep());
  });

  const drain = async (c: { req: { header: (name: string) => string | undefined }; json: (body: unknown, status?: number) => Response }) => {
    if (!webhookDrainToken && !cronSecret) return c.json({ error: "not_found", message: "Webhook drain is disabled." }, 404);
    const header = c.req.header("authorization");
    const allowed =
      (webhookDrainToken != null && bearerMatches(header, webhookDrainToken)) ||
      (cronSecret != null && bearerMatches(header, cronSecret));
    if (!allowed) return c.json({ error: "unauthenticated", message: "Drain token required." }, 401);
    return c.json(await bridge.drain());
  };
  app.get("/internal/webhook-drain", drain);
  app.post("/internal/webhook-drain", drain);

  app.get("/settings/:token", async (c) => html(c, settingsPage(await bridge.settingsView(c.req.param("token"), base(c, deps.baseUrl)))));

  app.post("/settings/:token", async (c) => {
    const token = c.req.param("token");
    const origin = base(c, deps.baseUrl);
    const body = await readObject(c);
    if (!body.ok) {
      if (wantsJson(c)) return c.json({ error: "invalid_input", message: body.message }, 400);
      return html(c, settingsPage(await bridge.settingsView(token, origin), body.message), 400);
    }
    const action = stringField(body.value, "action") ?? "save";
    if (action === "rotate") {
      const rotated = await bridge.rotateSettings(token, origin);
      if (!rotated.ok) {
        if (wantsJson(c)) return c.json({ error: rotated.error, message: rotated.message }, statusFor(rotated.error));
        return html(c, settingsPage(await bridge.settingsView(token, origin), rotated.message), statusFor(rotated.error));
      }
      if (wantsJson(c)) return c.json(rotated.data);
      return html(c, settingsRotatedPage(rotated.data.settings_url));
    }
    if (action === "remove") {
      const removed = await bridge.removeSettings(token, origin);
      if (!removed.ok) {
        if (wantsJson(c)) return c.json({ error: removed.error, message: removed.message }, statusFor(removed.error));
        return html(c, settingsPage(await bridge.settingsView(token, origin), removed.message), statusFor(removed.error));
      }
      if (wantsJson(c)) return c.json(removed.data);
      return html(c, settingsPage(removed.data));
    }
    const saved = await bridge.saveSettings(token, origin, {
      url: stringField(body.value, "url"),
      senderKey: stringField(body.value, "sender_key"),
      authScheme: stringField(body.value, "auth_scheme"),
      enabled: enabledField(body.value.enabled),
    });
    if (!saved.ok) {
      if (wantsJson(c)) return c.json({ error: saved.error, message: saved.message, ...saved.details }, statusFor(saved.error));
      const view = await bridge.settingsView(token, origin);
      return html(c, settingsPage(view, saved.message), statusFor(saved.error));
    }
    if (wantsJson(c)) return c.json(saved.data);
    return html(c, settingsPage(saved.data));
  });

  app.get("/bots/:botId", async (c) => {
    const owned = await ownedBot(c, deps.store, sessionSecret);
    if (!owned.ok) return owned.response;
    const connection = await deps.store.findConnection(owned.bot.bot_id, "google_drive");
    const capabilities = connection ? await deps.store.listCapabilities(connection.connection_id) : [];
    const grants = connection ? await deps.store.listGrants(connection.connection_id) : [];
    return html(
      c,
      botPage({
        botId: owned.bot.bot_id,
        displayName: owned.bot.display_name,
        csrf: owned.session.csrf,
        drive: connection
          ? { connected: connection.status === "active", label: connection.external_account_label, capabilities, grants }
          : { connected: false, label: null, capabilities: [], grants: [] },
      }),
    );
  });

  app.post("/bots/:botId/drive/connect", async (c) => {
    const owned = await ownedBot(c, deps.store, sessionSecret);
    if (!owned.ok) return owned.response;
    const body = await readObject(c);
    if (!body.ok || !csrfOk(body.value, owned.session)) return html(c, messagePage("Missing token", "Submit the form again."), 400);
    if (!sessionSecret) return html(c, messagePage("Not configured", "Set SESSION_SECRET before connecting Drive."), 400);
    const capabilities = stringList(body.value, "capability");
    const verifier = codeVerifier();
    const state = seal(sessionSecret, { provider: "google_drive", verifier, exp: Date.now() + 10 * 60 * 1000, purpose: "drive", bot_id: owned.bot.bot_id, capabilities });
    const redirectUri = `${base(c, deps.baseUrl)}/integrations/google-drive/callback`;
    const url = access.driveConnectUrl({ redirectUri, state, challenge: codeChallenge(verifier), capabilities });
    if (!url.ok) return html(c, messagePage("Drive is not configured", url.message), 400);
    setCookie(c, "bb_oauth", state, cookieOptions(base(c, deps.baseUrl), 600));
    return c.redirect(url.data, 302);
  });

  app.get("/integrations/google-drive/callback", async (c) => {
    const session = readSession(c, sessionSecret);
    if (!session || !sessionSecret) return c.redirect("/login", 303);
    const sealed = getCookie(c, "bb_oauth") ?? "";
    const pending = openOAuthState(sessionSecret, sealed);
    const code = c.req.query("code") ?? "";
    if (!pending || pending.purpose !== "drive" || c.req.query("state") !== sealed || !code || !pending.bot_id) {
      return html(c, messagePage("Drive connection failed", "Start the Drive connection again."), 400);
    }
    const bot = await deps.store.findBotById(pending.bot_id);
    if (!bot || bot.user_id !== session.user_id) return html(c, messagePage("Drive connection failed", "That bot is not on this account."), 403);
    const result = await access.finishDriveConnect({
      bot,
      code,
      verifier: pending.verifier,
      redirectUri: `${base(c, deps.baseUrl)}/integrations/google-drive/callback`,
      capabilities: pending.capabilities,
    });
    setCookie(c, "bb_oauth", "", cookieOptions(base(c, deps.baseUrl), 0));
    if (!result.ok) return html(c, messagePage("Drive connection failed", result.message), 400);
    return c.redirect(`/bots/${bot.bot_id}`, 303);
  });

  app.post("/bots/:botId/drive/capabilities", async (c) => {
    const owned = await ownedBot(c, deps.store, sessionSecret);
    if (!owned.ok) return owned.response;
    const body = await readObject(c);
    if (!body.ok || !csrfOk(body.value, owned.session)) return html(c, messagePage("Missing token", "Submit the form again."), 400);
    const result = await access.setCapabilities(owned.bot, stringList(body.value, "capability"));
    if (!result.ok) {
      return html(c, botPage({ botId: owned.bot.bot_id, displayName: owned.bot.display_name, csrf: owned.session.csrf, drive: null, error: result.message }), 400);
    }
    return c.redirect(`/bots/${owned.bot.bot_id}`, 303);
  });

  app.get("/bots/:botId/drive", async (c) => {
    const owned = await ownedBot(c, deps.store, sessionSecret);
    if (!owned.ok) return owned.response;
    const folder = c.req.query("folder") || undefined;
    const listed = await access.browse(owned.bot, folder);
    if (!listed.ok) return html(c, messagePage("Drive browse failed", listed.message), 400);
    return html(c, driveBrowsePage({ botId: owned.bot.bot_id, csrf: owned.session.csrf, folderId: folder ?? null, resources: listed.data.resources }));
  });

  app.post("/bots/:botId/grants", async (c) => {
    const owned = await ownedBot(c, deps.store, sessionSecret);
    if (!owned.ok) return owned.response;
    const body = await readObject(c);
    if (!body.ok || !csrfOk(body.value, owned.session)) return html(c, messagePage("Missing token", "Submit the form again."), 400);
    const externalId = stringField(body.value, "external_id") ?? "";
    const name = stringField(body.value, "name") ?? externalId;
    const kind = stringField(body.value, "kind") === "folder" ? "folder" : "file";
    const result = await access.grant(owned.bot, { kind, externalId, name });
    if (!result.ok) return html(c, messagePage("Grant failed", result.message), 400);
    return c.redirect(`/bots/${owned.bot.bot_id}`, 303);
  });

  app.post("/bots/:botId/grants/:grantId/revoke", async (c) => {
    const owned = await ownedBot(c, deps.store, sessionSecret);
    if (!owned.ok) return owned.response;
    const body = await readObject(c);
    if (!body.ok || !csrfOk(body.value, owned.session)) return html(c, messagePage("Missing token", "Submit the form again."), 400);
    await access.revokeGrant(owned.bot, c.req.param("grantId"));
    return c.redirect(`/bots/${owned.bot.bot_id}`, 303);
  });

  app.get("/access/:token", async (c) => {
    const session = readSession(c, sessionSecret);
    const view = await access.approvalFor(c.req.param("token"), session?.user_id ?? null);
    if (!view.ok) return html(c, messagePage("Approval unavailable", view.message), view.error === "forbidden" ? 403 : 404);
    return html(c, accessRequestPage({ externalId: view.data.external_id, kind: view.data.kind, status: view.data.status, csrf: session?.csrf ?? "" }));
  });

  app.post("/access/:token", async (c) => {
    const session = readSession(c, sessionSecret);
    if (!session) return c.redirect("/login", 303);
    const body = await readObject(c);
    const decision = body.ok ? stringField(body.value, "decision") : null;
    if (!body.ok || !csrfOk(body.value, session) || (decision !== "approve" && decision !== "deny")) {
      return html(c, messagePage("Missing decision", "Choose approve or deny."), 400);
    }
    const result = await access.decideAccess(c.req.param("token"), session.user_id, decision);
    if (!result.ok) return html(c, messagePage("Approval not recorded", result.message), 400);
    return html(c, messagePage("Drive access updated", `The request is ${result.data.status}.`));
  });

  app.on(["GET", "DELETE"], "/mcp", (c) => methodNotAllowed(c));
  app.on(["GET", "DELETE"], "/mcp/:token", (c) => methodNotAllowed(c));
  app.post("/mcp", (c) => handleMcp(c, bridge, access, base(c, deps.baseUrl)));
  app.post("/mcp/:token", (c) => handleMcp(c, bridge, access, base(c, deps.baseUrl)));

  app.notFound((c) => {
    if (wantsJson(c)) return c.json({ error: "not_found", message: "No such page." }, 404);
    return html(c, messagePage("Not found", "That page is not part of Bot Bridge."), 404);
  });

  app.onError((error, c) => {
    console.error("request_failed", error instanceof Error ? error.message : "error");
    return c.json({ error: "internal_error", message: "Something went wrong." }, 500);
  });

  return app;
}

async function handleMcp(
  c: {
    req: {
      param: (name: string) => string | undefined;
      raw: Request;
      header: (name: string) => string | undefined;
    };
  },
  bridge: Bridge,
  access: Access,
  baseUrl: string,
): Promise<Response> {
  const pathToken = c.req.param("token");
  const headerToken = tokenFromHeader(c.req.header("authorization"), c.req.header("x-bot-token"));
  if (pathToken && headerToken && pathToken !== headerToken) return unauthenticated();
  const token = pathToken || headerToken;
  const bot = token ? await bridge.authenticate(token) : null;
  if (!bot) return unauthenticated();
  const server = await createMcpServer(bridge, access, bot, baseUrl);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
    maxRequestBodySize: 64 * 1024,
  });
  try {
    await server.connect(transport);
    return await transport.handleRequest(c.req.raw);
  } catch (error) {
    console.error("mcp_failed", error instanceof Error ? error.name : "error");
    return Response.json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null }, { status: 500 });
  } finally {
    await transport.close().catch(() => undefined);
    await server.close().catch(() => undefined);
  }
}

function unauthenticated(): Response {
  return Response.json(
    {
      jsonrpc: "2.0",
      error: {
        code: -32001,
        message: "unauthenticated",
        data: { error: "unauthenticated", message: "Provide the bot token in the connector URL or as Authorization: Bearer." },
      },
      id: null,
    },
    { status: 401, headers: { "WWW-Authenticate": 'Bearer realm="bot-bridge"' } },
  );
}

function methodNotAllowed(c: { json: (body: unknown, status?: number) => Response }): Response {
  return c.json(
    { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed. This server is stateless. POST JSON-RPC to /mcp." }, id: null },
    405,
  );
}

function html(c: { body: (body: string, status?: number, headers?: Record<string, string>) => Response }, body: string, status = 200): Response {
  return c.body(body, status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
}

function wantsJson(c: { req: { header: (name: string) => string | undefined } }): boolean {
  const accept = c.req.header("accept") ?? "";
  const type = c.req.header("content-type") ?? "";
  return accept.includes("application/json") || type.includes("application/json");
}

function base(c: { req: { url: string } }, forced?: string): string {
  return resolveBaseUrl(c.req.url, forced);
}

export function resolveBaseUrl(requestUrl: string, forced?: string): string {
  if (forced) return forced.replace(/\/$/, "");
  const configured = process.env.PUBLIC_BASE_URL?.trim();
  if (configured) return configured.replace(/\/$/, "");
  const url = new URL(requestUrl);
  return `${url.protocol}//${url.host}`;
}

function clientIp(c: { req: { header: (name: string) => string | undefined } }): string {
  const real = c.req.header("x-real-ip")?.trim();
  if (real) return real;
  const vercel = c.req.header("x-vercel-forwarded-for")?.split(",")[0]?.trim();
  if (vercel) return vercel;
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded) {
    const parts = forwarded.split(",").map((part) => part.trim()).filter((part) => part.length > 0);
    const platform = parts[parts.length - 1];
    if (platform) return platform;
  }
  return "local";
}

const REGISTER_WINDOW_MS = 60 * 60 * 1000;

async function allowRegister(store: Store, ip: string, limit: number, now: Date): Promise<boolean> {
  return store.tryConsumeRate(`register:${sha256(ip)}`, now, REGISTER_WINDOW_MS, limit);
}

async function readObject(c: { req: { header: (name: string) => string | undefined; json: () => Promise<unknown>; parseBody: () => Promise<Record<string, unknown>> } }): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; message: string }> {
  const type = c.req.header("content-type") ?? "";
  try {
    if (type.includes("application/json")) {
      const value = await c.req.json();
      if (!value || typeof value !== "object" || Array.isArray(value)) return { ok: false, message: "JSON body must be an object." };
      return { ok: true, value: value as Record<string, unknown> };
    }
    const form = await c.req.parseBody();
    return { ok: true, value: form };
  } catch {
    return { ok: false, message: "Could not read the form." };
  }
}

function stringField(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  return typeof value === "string" ? value : undefined;
}

function enabledField(value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  return value === true || value === "true" || value === "on" || value === "yes";
}

function tokenFromHeader(authorization: string | undefined, alt: string | undefined): string | null {
  if (authorization?.toLowerCase().startsWith("bearer ")) {
    const token = authorization.slice(7).trim();
    if (token) return token;
  }
  if (alt?.trim()) return alt.trim();
  return null;
}

function bearerMatches(authorization: string | undefined, expected: string): boolean {
  const token = tokenFromHeader(authorization, undefined);
  if (!token) return false;
  return safeEqual(token, expected);
}

function cookieOptions(baseUrl: string, maxAge: number): { httpOnly: true; sameSite: "Lax"; path: "/"; secure: boolean; maxAge: number } {
  return { httpOnly: true, sameSite: "Lax", path: "/", secure: baseUrl.startsWith("https:"), maxAge };
}

function readSession(c: { req: { header: (name: string) => string | undefined } }, secret: string | null): SessionPayload | null {
  if (!secret) return null;
  const token = getCookie(c as never, "bb_session");
  if (!token) return null;
  return openSession(secret, token, new Date());
}

function loginLinks(oauth: OAuthConfig): Array<{ href: string; label: string }> {
  const links: Array<{ href: string; label: string }> = [];
  if (oauth.google) links.push({ href: "/auth/google", label: "Continue with Google" });
  if (oauth.github) links.push({ href: "/auth/github", label: "Continue with GitHub" });
  if (oauth.x) links.push({ href: "/auth/x", label: "Continue with X" });
  return links;
}

function oauthFromEnv(): OAuthConfig {
  const config: OAuthConfig = {};
  const googleId = process.env.GOOGLE_OAUTH_CLIENT_ID?.trim();
  const googleSecret = process.env.GOOGLE_OAUTH_CLIENT_SECRET?.trim();
  if (googleId && googleSecret) config.google = { clientId: googleId, clientSecret: googleSecret };
  const githubId = process.env.GITHUB_OAUTH_CLIENT_ID?.trim();
  const githubSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET?.trim();
  if (githubId && githubSecret) config.github = { clientId: githubId, clientSecret: githubSecret };
  const xId = process.env.X_OAUTH_CLIENT_ID?.trim();
  const xSecret = process.env.X_OAUTH_CLIENT_SECRET?.trim();
  if (xId && xSecret) config.x = { clientId: xId, clientSecret: xSecret };
  return config;
}

function driveClientFromEnv(oauth: OAuthConfig): DriveClientConfig | null {
  const id = process.env.GOOGLE_DRIVE_OAUTH_CLIENT_ID?.trim() || oauth.google?.clientId;
  const secret = process.env.GOOGLE_DRIVE_OAUTH_CLIENT_SECRET?.trim() || oauth.google?.clientSecret;
  if (!id || !secret) return null;
  return { clientId: id, clientSecret: secret };
}

function openOAuthState(secret: string, token: string): { provider: string; verifier: string; purpose: string; bot_id?: string; capabilities: string[] } | null {
  const parsed = openSealed(secret, token, new Date());
  if (!parsed || typeof parsed.provider !== "string" || typeof parsed.verifier !== "string" || typeof parsed.purpose !== "string") return null;
  const capabilities = Array.isArray(parsed.capabilities) ? parsed.capabilities.filter((item): item is string => typeof item === "string") : [];
  return { provider: parsed.provider, verifier: parsed.verifier, purpose: parsed.purpose, bot_id: typeof parsed.bot_id === "string" ? parsed.bot_id : undefined, capabilities };
}

async function ownedBot(
  c: Context,
  store: Store,
  secret: string | null,
): Promise<{ ok: true; session: SessionPayload; bot: BotRow } | { ok: false; response: Response }> {
  const session = readSession(c, secret);
  if (!session) return { ok: false, response: c.redirect("/login", 303) };
  const bot = await store.findBotById(c.req.param("botId") ?? "");
  if (!bot || bot.user_id !== session.user_id) return { ok: false, response: c.json({ error: "not_found", message: "That bot is not on this account." }, 404) };
  return { ok: true, session, bot };
}

function csrfOk(body: Record<string, unknown>, session: SessionPayload): boolean {
  return stringField(body, "csrf") === session.csrf;
}

function stringList(body: Record<string, unknown>, key: string): string[] {
  const value = body[key];
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return [];
}

function statusFor(error: string): 400 | 401 | 404 | 409 | 429 {
  if (error === "unauthenticated") return 401;
  if (error === "not_found" || error === "invite_not_found") return 404;
  if (error === "rate_limited") return 429;
  if (error === "waiting_for_peer" || error === "already_used" || error === "invite_taken" || error === "idempotency_conflict") return 409;
  return 400;
}

let pending: Promise<Hono> | null = null;

export function getApp(): Promise<Hono> {
  if (!pending) {
    pending = createDefaultApp().catch((error: unknown) => {
      pending = null;
      throw error;
    });
  }
  return pending;
}

async function createDefaultApp(): Promise<Hono> {
  const webhooks = webhookFeatureFromEnv();
  if (process.env.VERCEL && webhooks.enabled && !webhooks.kek) {
    throw new Error("WEBHOOK_KEK is required when WEBHOOKS_ENABLED=1.");
  }
  const store = await createDefaultStore();
  return createApp({ store, limits: limitsFromEnv(), webhooks });
}
